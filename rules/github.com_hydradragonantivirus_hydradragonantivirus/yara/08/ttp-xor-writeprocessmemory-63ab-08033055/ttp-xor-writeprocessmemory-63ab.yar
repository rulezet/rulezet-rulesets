rule TTP_XOR_WriteProcessMemory_63ab {
  strings:
    $key_63ab = { 34 d9 [2] 06 fb [2] 00 ce [2] 2e ce [2] 11 d2 }

  condition:
    any of them
}