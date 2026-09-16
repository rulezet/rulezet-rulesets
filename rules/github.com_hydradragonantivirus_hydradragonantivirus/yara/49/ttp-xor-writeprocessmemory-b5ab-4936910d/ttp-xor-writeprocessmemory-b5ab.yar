rule TTP_XOR_WriteProcessMemory_b5ab {
  strings:
    $key_b5ab = { e2 d9 [2] d0 fb [2] d6 ce [2] f8 ce [2] c7 d2 }

  condition:
    any of them
}