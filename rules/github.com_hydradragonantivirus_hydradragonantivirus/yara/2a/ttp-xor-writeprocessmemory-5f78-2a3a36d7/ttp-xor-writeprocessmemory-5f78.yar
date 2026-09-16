rule TTP_XOR_WriteProcessMemory_5f78 {
  strings:
    $key_5f78 = { 08 0a [2] 3a 28 [2] 3c 1d [2] 12 1d [2] 2d 01 }

  condition:
    any of them
}