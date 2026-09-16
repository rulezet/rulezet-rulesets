rule TTP_XOR_WriteProcessMemory_11ab {
  strings:
    $key_11ab = { 46 d9 [2] 74 fb [2] 72 ce [2] 5c ce [2] 63 d2 }

  condition:
    any of them
}