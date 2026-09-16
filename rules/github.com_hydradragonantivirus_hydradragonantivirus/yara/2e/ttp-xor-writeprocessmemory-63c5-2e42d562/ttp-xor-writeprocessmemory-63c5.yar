rule TTP_XOR_WriteProcessMemory_63c5 {
  strings:
    $key_63c5 = { 34 b7 [2] 06 95 [2] 00 a0 [2] 2e a0 [2] 11 bc }

  condition:
    any of them
}