rule TTP_XOR_WriteProcessMemory_2a9e {
  strings:
    $key_2a9e = { 7d ec [2] 4f ce [2] 49 fb [2] 67 fb [2] 58 e7 }

  condition:
    any of them
}