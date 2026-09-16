rule TTP_XOR_WriteProcessMemory_5989 {
  strings:
    $key_5989 = { 0e fb [2] 3c d9 [2] 3a ec [2] 14 ec [2] 2b f0 }

  condition:
    any of them
}