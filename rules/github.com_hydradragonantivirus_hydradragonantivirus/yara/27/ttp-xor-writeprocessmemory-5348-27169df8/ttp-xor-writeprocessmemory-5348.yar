rule TTP_XOR_WriteProcessMemory_5348 {
  strings:
    $key_5348 = { 04 3a [2] 36 18 [2] 30 2d [2] 1e 2d [2] 21 31 }

  condition:
    any of them
}