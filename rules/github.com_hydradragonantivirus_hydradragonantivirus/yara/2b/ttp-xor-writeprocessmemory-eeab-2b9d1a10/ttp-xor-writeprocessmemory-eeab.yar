rule TTP_XOR_WriteProcessMemory_eeab {
  strings:
    $key_eeab = { b9 d9 [2] 8b fb [2] 8d ce [2] a3 ce [2] 9c d2 }

  condition:
    any of them
}