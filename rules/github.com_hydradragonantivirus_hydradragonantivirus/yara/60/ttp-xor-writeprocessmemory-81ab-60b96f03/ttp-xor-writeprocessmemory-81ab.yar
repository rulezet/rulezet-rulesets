rule TTP_XOR_WriteProcessMemory_81ab {
  strings:
    $key_81ab = { d6 d9 [2] e4 fb [2] e2 ce [2] cc ce [2] f3 d2 }

  condition:
    any of them
}