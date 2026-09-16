rule TTP_XOR_WriteProcessMemory_45ab {
  strings:
    $key_45ab = { 12 d9 [2] 20 fb [2] 26 ce [2] 08 ce [2] 37 d2 }

  condition:
    any of them
}