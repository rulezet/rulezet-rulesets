rule TTP_XOR_WriteProcessMemory_b4ab {
  strings:
    $key_b4ab = { e3 d9 [2] d1 fb [2] d7 ce [2] f9 ce [2] c6 d2 }

  condition:
    any of them
}