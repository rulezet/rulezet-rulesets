rule TTP_XOR_WriteProcessMemory_6081 {
  strings:
    $key_6081 = { 37 f3 [2] 05 d1 [2] 03 e4 [2] 2d e4 [2] 12 f8 }

  condition:
    any of them
}