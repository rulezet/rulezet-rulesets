rule TTP_XOR_WriteProcessMemory_93ab {
  strings:
    $key_93ab = { c4 d9 [2] f6 fb [2] f0 ce [2] de ce [2] e1 d2 }

  condition:
    any of them
}