rule TTP_XOR_WriteProcessMemory_6574 {
  strings:
    $key_6574 = { 32 06 [2] 00 24 [2] 06 11 [2] 28 11 [2] 17 0d }

  condition:
    any of them
}