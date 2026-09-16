rule TTP_XOR_WriteProcessMemory_6989 {
  strings:
    $key_6989 = { 3e fb [2] 0c d9 [2] 0a ec [2] 24 ec [2] 1b f0 }

  condition:
    any of them
}