rule TTP_XOR_WriteProcessMemory_0c89 {
  strings:
    $key_0c89 = { 5b fb [2] 69 d9 [2] 6f ec [2] 41 ec [2] 7e f0 }

  condition:
    any of them
}