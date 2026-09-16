rule TTP_XOR_WriteProcessMemory_979e {
  strings:
    $key_979e = { c0 ec [2] f2 ce [2] f4 fb [2] da fb [2] e5 e7 }

  condition:
    any of them
}