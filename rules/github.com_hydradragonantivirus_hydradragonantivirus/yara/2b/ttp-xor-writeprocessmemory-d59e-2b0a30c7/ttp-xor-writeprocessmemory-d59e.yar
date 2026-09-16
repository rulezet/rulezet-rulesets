rule TTP_XOR_WriteProcessMemory_d59e {
  strings:
    $key_d59e = { 82 ec [2] b0 ce [2] b6 fb [2] 98 fb [2] a7 e7 }

  condition:
    any of them
}