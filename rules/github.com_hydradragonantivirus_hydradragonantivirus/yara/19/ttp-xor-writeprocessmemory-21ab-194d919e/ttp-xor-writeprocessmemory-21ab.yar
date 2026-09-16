rule TTP_XOR_WriteProcessMemory_21ab {
  strings:
    $key_21ab = { 76 d9 [2] 44 fb [2] 42 ce [2] 6c ce [2] 53 d2 }

  condition:
    any of them
}