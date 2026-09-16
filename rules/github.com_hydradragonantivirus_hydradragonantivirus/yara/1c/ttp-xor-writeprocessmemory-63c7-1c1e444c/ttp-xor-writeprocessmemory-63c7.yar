rule TTP_XOR_WriteProcessMemory_63c7 {
  strings:
    $key_63c7 = { 34 b5 [2] 06 97 [2] 00 a2 [2] 2e a2 [2] 11 be }

  condition:
    any of them
}