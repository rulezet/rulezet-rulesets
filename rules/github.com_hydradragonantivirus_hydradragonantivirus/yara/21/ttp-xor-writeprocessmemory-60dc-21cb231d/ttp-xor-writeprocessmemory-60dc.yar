rule TTP_XOR_WriteProcessMemory_60dc {
  strings:
    $key_60dc = { 37 ae [2] 05 8c [2] 03 b9 [2] 2d b9 [2] 12 a5 }

  condition:
    any of them
}