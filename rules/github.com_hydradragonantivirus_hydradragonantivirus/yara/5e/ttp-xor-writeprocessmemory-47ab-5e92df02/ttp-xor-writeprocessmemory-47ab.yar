rule TTP_XOR_WriteProcessMemory_47ab {
  strings:
    $key_47ab = { 10 d9 [2] 22 fb [2] 24 ce [2] 0a ce [2] 35 d2 }

  condition:
    any of them
}