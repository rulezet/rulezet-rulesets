rule TTP_XOR_WriteProcessMemory_329e {
  strings:
    $key_329e = { 65 ec [2] 57 ce [2] 51 fb [2] 7f fb [2] 40 e7 }

  condition:
    any of them
}