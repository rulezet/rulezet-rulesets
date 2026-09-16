rule TTP_XOR_WriteProcessMemory_919e {
  strings:
    $key_919e = { c6 ec [2] f4 ce [2] f2 fb [2] dc fb [2] e3 e7 }

  condition:
    any of them
}