rule TTP_XOR_WriteProcessMemory_a2ec {
  strings:
    $key_a2ec = { f5 9e [2] c7 bc [2] c1 89 [2] ef 89 [2] d0 95 }

  condition:
    any of them
}