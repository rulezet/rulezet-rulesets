rule TTP_XOR_WriteProcessMemory_33ab {
  strings:
    $key_33ab = { 64 d9 [2] 56 fb [2] 50 ce [2] 7e ce [2] 41 d2 }

  condition:
    any of them
}