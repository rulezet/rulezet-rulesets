rule TTP_XOR_WriteProcessMemory_6532 {
  strings:
    $key_6532 = { 32 40 [2] 00 62 [2] 06 57 [2] 28 57 [2] 17 4b }

  condition:
    any of them
}