rule TTP_XOR_WriteProcessMemory_b79e {
  strings:
    $key_b79e = { e0 ec [2] d2 ce [2] d4 fb [2] fa fb [2] c5 e7 }

  condition:
    any of them
}