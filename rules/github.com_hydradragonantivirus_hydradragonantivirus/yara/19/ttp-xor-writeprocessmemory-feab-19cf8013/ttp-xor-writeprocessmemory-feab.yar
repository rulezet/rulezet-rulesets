rule TTP_XOR_WriteProcessMemory_feab {
  strings:
    $key_feab = { a9 d9 [2] 9b fb [2] 9d ce [2] b3 ce [2] 8c d2 }

  condition:
    any of them
}