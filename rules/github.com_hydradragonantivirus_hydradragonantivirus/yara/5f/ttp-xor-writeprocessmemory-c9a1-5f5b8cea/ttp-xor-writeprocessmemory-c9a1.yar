rule TTP_XOR_WriteProcessMemory_c9a1 {
  strings:
    $key_c9a1 = { 9e d3 [2] ac f1 [2] aa c4 [2] 84 c4 [2] bb d8 }

  condition:
    any of them
}