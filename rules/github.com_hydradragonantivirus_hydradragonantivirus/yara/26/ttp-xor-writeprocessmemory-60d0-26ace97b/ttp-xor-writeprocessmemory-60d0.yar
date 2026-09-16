rule TTP_XOR_WriteProcessMemory_60d0 {
  strings:
    $key_60d0 = { 37 a2 [2] 05 80 [2] 03 b5 [2] 2d b5 [2] 12 a9 }

  condition:
    any of them
}