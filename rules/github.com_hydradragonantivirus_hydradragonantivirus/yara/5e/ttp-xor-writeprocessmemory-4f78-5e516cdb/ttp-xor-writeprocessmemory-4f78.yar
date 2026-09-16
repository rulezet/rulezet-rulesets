rule TTP_XOR_WriteProcessMemory_4f78 {
  strings:
    $key_4f78 = { 18 0a [2] 2a 28 [2] 2c 1d [2] 02 1d [2] 3d 01 }

  condition:
    any of them
}