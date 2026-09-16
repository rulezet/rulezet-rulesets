rule TTP_XOR_WriteProcessMemory_60f5 {
  strings:
    $key_60f5 = { 37 87 [2] 05 a5 [2] 03 90 [2] 2d 90 [2] 12 8c }

  condition:
    any of them
}