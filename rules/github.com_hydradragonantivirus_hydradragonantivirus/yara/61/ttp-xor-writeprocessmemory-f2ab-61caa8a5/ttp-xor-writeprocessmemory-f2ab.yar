rule TTP_XOR_WriteProcessMemory_f2ab {
  strings:
    $key_f2ab = { a5 d9 [2] 97 fb [2] 91 ce [2] bf ce [2] 80 d2 }

  condition:
    any of them
}