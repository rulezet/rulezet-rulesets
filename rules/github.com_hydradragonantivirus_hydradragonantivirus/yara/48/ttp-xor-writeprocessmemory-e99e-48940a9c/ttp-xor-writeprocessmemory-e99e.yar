rule TTP_XOR_WriteProcessMemory_e99e {
  strings:
    $key_e99e = { be ec [2] 8c ce [2] 8a fb [2] a4 fb [2] 9b e7 }

  condition:
    any of them
}