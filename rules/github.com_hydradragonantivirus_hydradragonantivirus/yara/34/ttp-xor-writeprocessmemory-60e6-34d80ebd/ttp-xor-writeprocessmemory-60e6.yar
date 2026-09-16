rule TTP_XOR_WriteProcessMemory_60e6 {
  strings:
    $key_60e6 = { 37 94 [2] 05 b6 [2] 03 83 [2] 2d 83 [2] 12 9f }

  condition:
    any of them
}