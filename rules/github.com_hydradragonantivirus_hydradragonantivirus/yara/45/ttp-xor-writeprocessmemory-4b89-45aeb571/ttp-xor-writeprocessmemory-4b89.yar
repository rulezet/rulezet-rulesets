rule TTP_XOR_WriteProcessMemory_4b89 {
  strings:
    $key_4b89 = { 1c fb [2] 2e d9 [2] 28 ec [2] 06 ec [2] 39 f0 }

  condition:
    any of them
}