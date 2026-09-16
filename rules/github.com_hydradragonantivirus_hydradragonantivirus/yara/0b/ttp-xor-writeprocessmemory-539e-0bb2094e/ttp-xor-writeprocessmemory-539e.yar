rule TTP_XOR_WriteProcessMemory_539e {
  strings:
    $key_539e = { 04 ec [2] 36 ce [2] 30 fb [2] 1e fb [2] 21 e7 }

  condition:
    any of them
}