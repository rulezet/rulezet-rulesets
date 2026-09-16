rule TTP_XOR_WriteProcessMemory_b59e {
  strings:
    $key_b59e = { e2 ec [2] d0 ce [2] d6 fb [2] f8 fb [2] c7 e7 }

  condition:
    any of them
}