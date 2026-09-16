rule TTP_XOR_WriteProcessMemory_5772 {
  strings:
    $key_5772 = { 00 00 [2] 32 22 [2] 34 17 [2] 1a 17 [2] 25 0b }

  condition:
    any of them
}