rule TTP_XOR_WriteProcessMemory_5726 {
  strings:
    $key_5726 = { 00 54 [2] 32 76 [2] 34 43 [2] 1a 43 [2] 25 5f }

  condition:
    any of them
}