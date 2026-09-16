rule TTP_XOR_WriteProcessMemory_029e {
  strings:
    $key_029e = { 55 ec [2] 67 ce [2] 61 fb [2] 4f fb [2] 70 e7 }

  condition:
    any of them
}