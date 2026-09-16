rule TTP_XOR_WriteProcessMemory_3c89 {
  strings:
    $key_3c89 = { 6b fb [2] 59 d9 [2] 5f ec [2] 71 ec [2] 4e f0 }

  condition:
    any of them
}