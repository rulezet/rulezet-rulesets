rule TTP_XOR_WriteProcessMemory_2ca1 {
  strings:
    $key_2ca1 = { 7b d3 [2] 49 f1 [2] 4f c4 [2] 61 c4 [2] 5e d8 }

  condition:
    any of them
}