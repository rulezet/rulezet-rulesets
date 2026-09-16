rule TTP_XOR_WriteProcessMemory_4713 {
  strings:
    $key_4713 = { 10 61 [2] 22 43 [2] 24 76 [2] 0a 76 [2] 35 6a }

  condition:
    any of them
}