rule TTP_XOR_WriteProcessMemory_50d7 {
  strings:
    $key_50d7 = { 07 a5 [2] 35 87 [2] 33 b2 [2] 1d b2 [2] 22 ae }

  condition:
    any of them
}