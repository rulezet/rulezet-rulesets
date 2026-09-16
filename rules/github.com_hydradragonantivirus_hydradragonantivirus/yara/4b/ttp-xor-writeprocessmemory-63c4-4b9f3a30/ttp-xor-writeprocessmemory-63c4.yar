rule TTP_XOR_WriteProcessMemory_63c4 {
  strings:
    $key_63c4 = { 34 b6 [2] 06 94 [2] 00 a1 [2] 2e a1 [2] 11 bd }

  condition:
    any of them
}