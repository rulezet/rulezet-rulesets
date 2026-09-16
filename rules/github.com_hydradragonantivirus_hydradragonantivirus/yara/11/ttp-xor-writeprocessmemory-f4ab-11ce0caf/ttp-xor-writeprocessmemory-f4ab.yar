rule TTP_XOR_WriteProcessMemory_f4ab {
  strings:
    $key_f4ab = { a3 d9 [2] 91 fb [2] 97 ce [2] b9 ce [2] 86 d2 }

  condition:
    any of them
}