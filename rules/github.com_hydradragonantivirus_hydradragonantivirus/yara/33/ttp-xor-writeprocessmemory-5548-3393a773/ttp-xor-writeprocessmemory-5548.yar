rule TTP_XOR_WriteProcessMemory_5548 {
  strings:
    $key_5548 = { 02 3a [2] 30 18 [2] 36 2d [2] 18 2d [2] 27 31 }

  condition:
    any of them
}