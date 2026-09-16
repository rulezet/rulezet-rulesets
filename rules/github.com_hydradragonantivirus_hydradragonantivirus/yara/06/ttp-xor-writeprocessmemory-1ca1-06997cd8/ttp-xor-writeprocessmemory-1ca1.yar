rule TTP_XOR_WriteProcessMemory_1ca1 {
  strings:
    $key_1ca1 = { 4b d3 [2] 79 f1 [2] 7f c4 [2] 51 c4 [2] 6e d8 }

  condition:
    any of them
}