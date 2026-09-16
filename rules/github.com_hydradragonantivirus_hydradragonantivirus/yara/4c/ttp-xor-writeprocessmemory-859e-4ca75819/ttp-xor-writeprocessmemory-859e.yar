rule TTP_XOR_WriteProcessMemory_859e {
  strings:
    $key_859e = { d2 ec [2] e0 ce [2] e6 fb [2] c8 fb [2] f7 e7 }

  condition:
    any of them
}