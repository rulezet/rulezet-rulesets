rule TTP_XOR_WriteProcessMemory_fb81 {
  strings:
    $key_fb81 = { ac f3 [2] 9e d1 [2] 98 e4 [2] b6 e4 [2] 89 f8 }

  condition:
    any of them
}