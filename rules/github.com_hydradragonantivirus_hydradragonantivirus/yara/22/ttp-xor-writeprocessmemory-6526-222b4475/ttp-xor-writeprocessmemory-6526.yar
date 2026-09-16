rule TTP_XOR_WriteProcessMemory_6526 {
  strings:
    $key_6526 = { 32 54 [2] 00 76 [2] 06 43 [2] 28 43 [2] 17 5f }

  condition:
    any of them
}