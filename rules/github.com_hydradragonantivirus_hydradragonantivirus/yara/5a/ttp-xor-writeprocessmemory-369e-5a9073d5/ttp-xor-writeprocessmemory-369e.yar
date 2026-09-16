rule TTP_XOR_WriteProcessMemory_369e {
  strings:
    $key_369e = { 61 ec [2] 53 ce [2] 55 fb [2] 7b fb [2] 44 e7 }

  condition:
    any of them
}