rule TTP_XOR_WriteProcessMemory_6546 {
  strings:
    $key_6546 = { 32 34 [2] 00 16 [2] 06 23 [2] 28 23 [2] 17 3f }

  condition:
    any of them
}