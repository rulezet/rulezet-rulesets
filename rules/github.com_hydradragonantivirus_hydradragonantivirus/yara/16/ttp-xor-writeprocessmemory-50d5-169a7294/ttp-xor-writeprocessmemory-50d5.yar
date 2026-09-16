rule TTP_XOR_WriteProcessMemory_50d5 {
  strings:
    $key_50d5 = { 07 a7 [2] 35 85 [2] 33 b0 [2] 1d b0 [2] 22 ac }

  condition:
    any of them
}