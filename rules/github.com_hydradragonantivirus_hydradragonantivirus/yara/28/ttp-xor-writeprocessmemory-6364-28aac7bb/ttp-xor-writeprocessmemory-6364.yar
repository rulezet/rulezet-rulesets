rule TTP_XOR_WriteProcessMemory_6364 {
  strings:
    $key_6364 = { 34 16 [2] 06 34 [2] 00 01 [2] 2e 01 [2] 11 1d }

  condition:
    any of them
}