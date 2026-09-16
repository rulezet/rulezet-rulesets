rule TTP_XOR_WriteProcessMemory_d89e {
  strings:
    $key_d89e = { 8f ec [2] bd ce [2] bb fb [2] 95 fb [2] aa e7 }

  condition:
    any of them
}