rule TTP_XOR_WriteProcessMemory_0989 {
  strings:
    $key_0989 = { 5e fb [2] 6c d9 [2] 6a ec [2] 44 ec [2] 7b f0 }

  condition:
    any of them
}