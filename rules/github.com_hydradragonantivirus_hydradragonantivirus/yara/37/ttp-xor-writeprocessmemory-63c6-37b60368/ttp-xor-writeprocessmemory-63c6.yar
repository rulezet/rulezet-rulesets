rule TTP_XOR_WriteProcessMemory_63c6 {
  strings:
    $key_63c6 = { 34 b4 [2] 06 96 [2] 00 a3 [2] 2e a3 [2] 11 bf }

  condition:
    any of them
}