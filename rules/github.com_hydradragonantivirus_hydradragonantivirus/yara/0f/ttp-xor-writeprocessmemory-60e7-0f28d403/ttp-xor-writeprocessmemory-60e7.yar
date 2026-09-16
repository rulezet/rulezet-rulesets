rule TTP_XOR_WriteProcessMemory_60e7 {
  strings:
    $key_60e7 = { 37 95 [2] 05 b7 [2] 03 82 [2] 2d 82 [2] 12 9e }

  condition:
    any of them
}