rule TTP_XOR_WriteProcessMemory_e79e {
  strings:
    $key_e79e = { b0 ec [2] 82 ce [2] 84 fb [2] aa fb [2] 95 e7 }

  condition:
    any of them
}