rule TTP_XOR_WriteProcessMemory_a6ab {
  strings:
    $key_a6ab = { f1 d9 [2] c3 fb [2] c5 ce [2] eb ce [2] d4 d2 }

  condition:
    any of them
}