rule TTP_XOR_WriteProcessMemory_90ab {
  strings:
    $key_90ab = { c7 d9 [2] f5 fb [2] f3 ce [2] dd ce [2] e2 d2 }

  condition:
    any of them
}