rule TTP_XOR_WriteProcessMemory_0ca1 {
  strings:
    $key_0ca1 = { 5b d3 [2] 69 f1 [2] 6f c4 [2] 41 c4 [2] 7e d8 }

  condition:
    any of them
}