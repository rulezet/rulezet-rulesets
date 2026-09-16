rule TTP_XOR_WriteProcessMemory_6463 {
  strings:
    $key_6463 = { 33 11 [2] 01 33 [2] 07 06 [2] 29 06 [2] 16 1a }

  condition:
    any of them
}