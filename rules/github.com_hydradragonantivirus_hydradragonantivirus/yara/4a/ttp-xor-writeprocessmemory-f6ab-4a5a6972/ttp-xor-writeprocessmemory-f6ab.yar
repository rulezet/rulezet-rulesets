rule TTP_XOR_WriteProcessMemory_f6ab {
  strings:
    $key_f6ab = { a1 d9 [2] 93 fb [2] 95 ce [2] bb ce [2] 84 d2 }

  condition:
    any of them
}