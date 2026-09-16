rule TTP_XOR_WriteProcessMemory_de81 {
  strings:
    $key_de81 = { 89 f3 [2] bb d1 [2] bd e4 [2] 93 e4 [2] ac f8 }

  condition:
    any of them
}