rule TTP_XOR_WriteProcessMemory_50d0 {
  strings:
    $key_50d0 = { 07 a2 [2] 35 80 [2] 33 b5 [2] 1d b5 [2] 22 a9 }

  condition:
    any of them
}