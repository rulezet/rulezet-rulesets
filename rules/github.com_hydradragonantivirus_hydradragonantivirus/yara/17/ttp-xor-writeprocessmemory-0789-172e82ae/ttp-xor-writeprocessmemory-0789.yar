rule TTP_XOR_WriteProcessMemory_0789 {
  strings:
    $key_0789 = { 50 fb [2] 62 d9 [2] 64 ec [2] 4a ec [2] 75 f0 }

  condition:
    any of them
}