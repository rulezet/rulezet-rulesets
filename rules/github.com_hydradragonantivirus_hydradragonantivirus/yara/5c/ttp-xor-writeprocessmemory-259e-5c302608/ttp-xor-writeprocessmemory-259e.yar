rule TTP_XOR_WriteProcessMemory_259e {
  strings:
    $key_259e = { 72 ec [2] 40 ce [2] 46 fb [2] 68 fb [2] 57 e7 }

  condition:
    any of them
}