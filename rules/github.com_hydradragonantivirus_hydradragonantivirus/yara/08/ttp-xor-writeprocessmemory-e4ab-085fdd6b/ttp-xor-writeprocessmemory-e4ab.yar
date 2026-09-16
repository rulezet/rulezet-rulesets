rule TTP_XOR_WriteProcessMemory_e4ab {
  strings:
    $key_e4ab = { b3 d9 [2] 81 fb [2] 87 ce [2] a9 ce [2] 96 d2 }

  condition:
    any of them
}