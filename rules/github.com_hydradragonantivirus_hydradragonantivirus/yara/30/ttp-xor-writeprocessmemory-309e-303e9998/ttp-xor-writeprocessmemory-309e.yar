rule TTP_XOR_WriteProcessMemory_309e {
  strings:
    $key_309e = { 67 ec [2] 55 ce [2] 53 fb [2] 7d fb [2] 42 e7 }

  condition:
    any of them
}