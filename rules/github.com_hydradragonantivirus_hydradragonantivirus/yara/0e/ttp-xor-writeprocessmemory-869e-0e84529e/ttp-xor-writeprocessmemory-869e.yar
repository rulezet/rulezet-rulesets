rule TTP_XOR_WriteProcessMemory_869e {
  strings:
    $key_869e = { d1 ec [2] e3 ce [2] e5 fb [2] cb fb [2] f4 e7 }

  condition:
    any of them
}