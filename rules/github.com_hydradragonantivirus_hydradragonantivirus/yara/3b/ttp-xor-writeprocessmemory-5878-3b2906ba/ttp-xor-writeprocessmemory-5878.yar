rule TTP_XOR_WriteProcessMemory_5878 {
  strings:
    $key_5878 = { 0f 0a [2] 3d 28 [2] 3b 1d [2] 15 1d [2] 2a 01 }

  condition:
    any of them
}