rule TTP_XOR_WriteProcessMemory_4046 {
  strings:
    $key_4046 = { 17 34 [2] 25 16 [2] 23 23 [2] 0d 23 [2] 32 3f }

  condition:
    any of them
}