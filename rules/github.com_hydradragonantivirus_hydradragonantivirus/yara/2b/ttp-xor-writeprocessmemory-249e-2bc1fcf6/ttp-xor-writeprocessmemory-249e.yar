rule TTP_XOR_WriteProcessMemory_249e {
  strings:
    $key_249e = { 73 ec [2] 41 ce [2] 47 fb [2] 69 fb [2] 56 e7 }

  condition:
    any of them
}