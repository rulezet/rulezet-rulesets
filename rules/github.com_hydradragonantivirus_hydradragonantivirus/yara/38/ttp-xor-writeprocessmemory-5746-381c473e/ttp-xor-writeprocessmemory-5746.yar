rule TTP_XOR_WriteProcessMemory_5746 {
  strings:
    $key_5746 = { 00 34 [2] 32 16 [2] 34 23 [2] 1a 23 [2] 25 3f }

  condition:
    any of them
}