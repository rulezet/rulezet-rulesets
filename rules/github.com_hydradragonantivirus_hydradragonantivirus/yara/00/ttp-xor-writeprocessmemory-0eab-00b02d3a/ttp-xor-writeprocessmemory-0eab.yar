rule TTP_XOR_WriteProcessMemory_0eab {
  strings:
    $key_0eab = { 59 d9 [2] 6b fb [2] 6d ce [2] 43 ce [2] 7c d2 }

  condition:
    any of them
}