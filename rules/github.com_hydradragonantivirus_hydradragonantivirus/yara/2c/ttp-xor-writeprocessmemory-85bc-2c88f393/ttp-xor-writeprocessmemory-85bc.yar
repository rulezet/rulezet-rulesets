rule TTP_XOR_WriteProcessMemory_85bc {
  strings:
    $key_85bc = { d2 ce [2] e0 ec [2] e6 d9 [2] c8 d9 [2] f7 c5 }

  condition:
    any of them
}