rule TTP_XOR_WriteProcessMemory_b2ec {
  strings:
    $key_b2ec = { e5 9e [2] d7 bc [2] d1 89 [2] ff 89 [2] c0 95 }

  condition:
    any of them
}