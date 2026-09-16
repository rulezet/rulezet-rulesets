rule TTP_XOR_WriteProcessMemory_b2ab {
  strings:
    $key_b2ab = { e5 d9 [2] d7 fb [2] d1 ce [2] ff ce [2] c0 d2 }

  condition:
    any of them
}