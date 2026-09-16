rule TTP_XOR_WriteProcessMemory_60f8 {
  strings:
    $key_60f8 = { 37 8a [2] 05 a8 [2] 03 9d [2] 2d 9d [2] 12 81 }

  condition:
    any of them
}