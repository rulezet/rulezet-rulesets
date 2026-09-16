rule TTP_XOR_WriteProcessMemory_e4ec {
  strings:
    $key_e4ec = { b3 9e [2] 81 bc [2] 87 89 [2] a9 89 [2] 96 95 }

  condition:
    any of them
}