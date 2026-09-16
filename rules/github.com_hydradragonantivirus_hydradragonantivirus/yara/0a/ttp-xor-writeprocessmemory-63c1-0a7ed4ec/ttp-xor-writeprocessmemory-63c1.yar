rule TTP_XOR_WriteProcessMemory_63c1 {
  strings:
    $key_63c1 = { 34 b3 [2] 06 91 [2] 00 a4 [2] 2e a4 [2] 11 b8 }

  condition:
    any of them
}