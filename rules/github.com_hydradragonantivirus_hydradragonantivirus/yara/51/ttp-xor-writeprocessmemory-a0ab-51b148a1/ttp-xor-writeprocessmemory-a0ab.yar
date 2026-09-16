rule TTP_XOR_WriteProcessMemory_a0ab {
  strings:
    $key_a0ab = { f7 d9 [2] c5 fb [2] c3 ce [2] ed ce [2] d2 d2 }

  condition:
    any of them
}