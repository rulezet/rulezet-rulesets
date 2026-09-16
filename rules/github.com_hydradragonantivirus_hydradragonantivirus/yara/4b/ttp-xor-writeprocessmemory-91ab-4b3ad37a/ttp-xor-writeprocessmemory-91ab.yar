rule TTP_XOR_WriteProcessMemory_91ab {
  strings:
    $key_91ab = { c6 d9 [2] f4 fb [2] f2 ce [2] dc ce [2] e3 d2 }

  condition:
    any of them
}