rule TTP_XOR_WriteProcessMemory_35ab {
  strings:
    $key_35ab = { 62 d9 [2] 50 fb [2] 56 ce [2] 78 ce [2] 47 d2 }

  condition:
    any of them
}