rule TTP_XOR_WriteProcessMemory_159e {
  strings:
    $key_159e = { 42 ec [2] 70 ce [2] 76 fb [2] 58 fb [2] 67 e7 }

  condition:
    any of them
}