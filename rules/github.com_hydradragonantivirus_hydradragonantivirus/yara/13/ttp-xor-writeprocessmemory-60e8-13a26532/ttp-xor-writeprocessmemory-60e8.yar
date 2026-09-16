rule TTP_XOR_WriteProcessMemory_60e8 {
  strings:
    $key_60e8 = { 37 9a [2] 05 b8 [2] 03 8d [2] 2d 8d [2] 12 91 }

  condition:
    any of them
}