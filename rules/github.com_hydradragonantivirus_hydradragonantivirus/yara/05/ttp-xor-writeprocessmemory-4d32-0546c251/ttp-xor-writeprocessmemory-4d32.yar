rule TTP_XOR_WriteProcessMemory_4d32 {
  strings:
    $key_4d32 = { 1a 40 [2] 28 62 [2] 2e 57 [2] 00 57 [2] 3f 4b }

  condition:
    any of them
}