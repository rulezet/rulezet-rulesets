rule TTP_XOR_WriteProcessMemory_1eab {
  strings:
    $key_1eab = { 49 d9 [2] 7b fb [2] 7d ce [2] 53 ce [2] 6c d2 }

  condition:
    any of them
}