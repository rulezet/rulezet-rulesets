rule TTP_XOR_WriteProcessMemory_3b89 {
  strings:
    $key_3b89 = { 6c fb [2] 5e d9 [2] 58 ec [2] 76 ec [2] 49 f0 }

  condition:
    any of them
}