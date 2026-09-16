rule TTP_XOR_WriteProcessMemory_60dd {
  strings:
    $key_60dd = { 37 af [2] 05 8d [2] 03 b8 [2] 2d b8 [2] 12 a4 }

  condition:
    any of them
}