rule TTP_XOR_WriteProcessMemory_1d32 {
  strings:
    $key_1d32 = { 4a 40 [2] 78 62 [2] 7e 57 [2] 50 57 [2] 6f 4b }

  condition:
    any of them
}