rule TTP_XOR_WriteProcessMemory_1dab {
  strings:
    $key_1dab = { 4a d9 [2] 78 fb [2] 7e ce [2] 50 ce [2] 6f d2 }

  condition:
    any of them
}