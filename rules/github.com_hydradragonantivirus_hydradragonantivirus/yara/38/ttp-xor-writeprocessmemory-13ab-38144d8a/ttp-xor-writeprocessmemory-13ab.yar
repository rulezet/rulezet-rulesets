rule TTP_XOR_WriteProcessMemory_13ab {
  strings:
    $key_13ab = { 44 d9 [2] 76 fb [2] 70 ce [2] 5e ce [2] 61 d2 }

  condition:
    any of them
}