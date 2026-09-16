rule TTP_XOR_WriteProcessMemory_3989 {
  strings:
    $key_3989 = { 6e fb [2] 5c d9 [2] 5a ec [2] 74 ec [2] 4b f0 }

  condition:
    any of them
}