rule TTP_XOR_WriteProcessMemory_72ab {
  strings:
    $key_72ab = { 25 d9 [2] 17 fb [2] 11 ce [2] 3f ce [2] 00 d2 }

  condition:
    any of them
}