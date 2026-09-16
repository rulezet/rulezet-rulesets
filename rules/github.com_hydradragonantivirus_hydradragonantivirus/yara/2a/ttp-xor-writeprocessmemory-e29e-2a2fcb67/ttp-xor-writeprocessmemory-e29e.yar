rule TTP_XOR_WriteProcessMemory_e29e {
  strings:
    $key_e29e = { b5 ec [2] 87 ce [2] 81 fb [2] af fb [2] 90 e7 }

  condition:
    any of them
}