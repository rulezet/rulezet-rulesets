rule TTP_XOR_WriteProcessMemory_63c0 {
  strings:
    $key_63c0 = { 34 b2 [2] 06 90 [2] 00 a5 [2] 2e a5 [2] 11 b9 }

  condition:
    any of them
}