rule TTP_XOR_WriteProcessMemory_7989 {
  strings:
    $key_7989 = { 2e fb [2] 1c d9 [2] 1a ec [2] 34 ec [2] 0b f0 }

  condition:
    any of them
}