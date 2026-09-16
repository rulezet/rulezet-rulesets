rule TTP_XOR_WriteProcessMemory_5789 {
  strings:
    $key_5789 = { 00 fb [2] 32 d9 [2] 34 ec [2] 1a ec [2] 25 f0 }

  condition:
    any of them
}