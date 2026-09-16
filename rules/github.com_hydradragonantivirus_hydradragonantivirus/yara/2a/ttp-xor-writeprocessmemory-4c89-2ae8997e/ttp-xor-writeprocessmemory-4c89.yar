rule TTP_XOR_WriteProcessMemory_4c89 {
  strings:
    $key_4c89 = { 1b fb [2] 29 d9 [2] 2f ec [2] 01 ec [2] 3e f0 }

  condition:
    any of them
}