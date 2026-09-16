rule TTP_XOR_WriteProcessMemory_55ab {
  strings:
    $key_55ab = { 02 d9 [2] 30 fb [2] 36 ce [2] 18 ce [2] 27 d2 }

  condition:
    any of them
}