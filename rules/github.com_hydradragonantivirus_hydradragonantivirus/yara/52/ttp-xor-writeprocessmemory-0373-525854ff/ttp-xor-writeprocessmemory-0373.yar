rule TTP_XOR_WriteProcessMemory_0373 {
  strings:
    $key_0373 = { 54 01 [2] 66 23 [2] 60 16 [2] 4e 16 [2] 71 0a }

  condition:
    any of them
}