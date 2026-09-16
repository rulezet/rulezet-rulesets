rule TTP_XOR_WriteProcessMemory_4eab {
  strings:
    $key_4eab = { 19 d9 [2] 2b fb [2] 2d ce [2] 03 ce [2] 3c d2 }

  condition:
    any of them
}