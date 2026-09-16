rule TTP_XOR_WriteProcessMemory_149e {
  strings:
    $key_149e = { 43 ec [2] 71 ce [2] 77 fb [2] 59 fb [2] 66 e7 }

  condition:
    any of them
}