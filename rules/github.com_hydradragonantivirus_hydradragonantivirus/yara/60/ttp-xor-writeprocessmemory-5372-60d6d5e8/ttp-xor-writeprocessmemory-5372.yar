rule TTP_XOR_WriteProcessMemory_5372 {
  strings:
    $key_5372 = { 04 00 [2] 36 22 [2] 30 17 [2] 1e 17 [2] 21 0b }

  condition:
    any of them
}