rule TTP_XOR_WriteProcessMemory_67ab {
  strings:
    $key_67ab = { 30 d9 [2] 02 fb [2] 04 ce [2] 2a ce [2] 15 d2 }

  condition:
    any of them
}