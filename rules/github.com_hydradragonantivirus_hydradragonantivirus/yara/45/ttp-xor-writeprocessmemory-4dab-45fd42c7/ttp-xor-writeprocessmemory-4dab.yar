rule TTP_XOR_WriteProcessMemory_4dab {
  strings:
    $key_4dab = { 1a d9 [2] 28 fb [2] 2e ce [2] 00 ce [2] 3f d2 }

  condition:
    any of them
}