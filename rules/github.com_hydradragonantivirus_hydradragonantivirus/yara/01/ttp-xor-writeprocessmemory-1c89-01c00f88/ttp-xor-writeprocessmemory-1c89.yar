rule TTP_XOR_WriteProcessMemory_1c89 {
  strings:
    $key_1c89 = { 4b fb [2] 79 d9 [2] 7f ec [2] 51 ec [2] 6e f0 }

  condition:
    any of them
}