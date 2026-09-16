rule TTP_XOR_WriteProcessMemory_74ab {
  strings:
    $key_74ab = { 23 d9 [2] 11 fb [2] 17 ce [2] 39 ce [2] 06 d2 }

  condition:
    any of them
}