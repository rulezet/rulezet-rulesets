rule TTP_XOR_WriteProcessMemory_f3ab {
  strings:
    $key_f3ab = { a4 d9 [2] 96 fb [2] 90 ce [2] be ce [2] 81 d2 }

  condition:
    any of them
}