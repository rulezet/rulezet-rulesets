rule TTP_XOR_WriteProcessMemory_63db {
  strings:
    $key_63db = { 34 a9 [2] 06 8b [2] 00 be [2] 2e be [2] 11 a2 }

  condition:
    any of them
}