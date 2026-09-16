rule TTP_XOR_WriteProcessMemory_97ab {
  strings:
    $key_97ab = { c0 d9 [2] f2 fb [2] f4 ce [2] da ce [2] e5 d2 }

  condition:
    any of them
}