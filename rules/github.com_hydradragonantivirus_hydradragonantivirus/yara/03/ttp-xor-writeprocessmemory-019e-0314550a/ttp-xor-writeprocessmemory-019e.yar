rule TTP_XOR_WriteProcessMemory_019e {
  strings:
    $key_019e = { 56 ec [2] 64 ce [2] 62 fb [2] 4c fb [2] 73 e7 }

  condition:
    any of them
}