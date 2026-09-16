rule TTP_XOR_WriteProcessMemory_85ab {
  strings:
    $key_85ab = { d2 d9 [2] e0 fb [2] e6 ce [2] c8 ce [2] f7 d2 }

  condition:
    any of them
}