rule TTP_XOR_WriteProcessMemory_5c89 {
  strings:
    $key_5c89 = { 0b fb [2] 39 d9 [2] 3f ec [2] 11 ec [2] 2e f0 }

  condition:
    any of them
}