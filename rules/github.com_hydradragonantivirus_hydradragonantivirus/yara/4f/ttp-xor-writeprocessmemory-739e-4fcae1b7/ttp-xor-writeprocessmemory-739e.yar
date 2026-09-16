rule TTP_XOR_WriteProcessMemory_739e {
  strings:
    $key_739e = { 24 ec [2] 16 ce [2] 10 fb [2] 3e fb [2] 01 e7 }

  condition:
    any of them
}