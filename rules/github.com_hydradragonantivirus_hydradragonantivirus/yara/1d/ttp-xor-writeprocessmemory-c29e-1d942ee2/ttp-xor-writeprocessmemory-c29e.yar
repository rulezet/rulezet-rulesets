rule TTP_XOR_WriteProcessMemory_c29e {
  strings:
    $key_c29e = { 95 ec [2] a7 ce [2] a1 fb [2] 8f fb [2] b0 e7 }

  condition:
    any of them
}