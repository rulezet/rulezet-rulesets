rule TTP_XOR_WriteProcessMemory_b1ec {
  strings:
    $key_b1ec = { e6 9e [2] d4 bc [2] d2 89 [2] fc 89 [2] c3 95 }

  condition:
    any of them
}