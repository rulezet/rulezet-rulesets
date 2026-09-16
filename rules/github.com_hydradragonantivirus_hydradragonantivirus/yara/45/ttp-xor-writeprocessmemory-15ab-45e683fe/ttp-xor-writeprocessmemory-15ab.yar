rule TTP_XOR_WriteProcessMemory_15ab {
  strings:
    $key_15ab = { 42 d9 [2] 70 fb [2] 76 ce [2] 58 ce [2] 67 d2 }

  condition:
    any of them
}