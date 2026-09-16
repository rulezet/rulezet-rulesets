rule TTP_XOR_WriteProcessMemory_c39e {
  strings:
    $key_c39e = { 94 ec [2] a6 ce [2] a0 fb [2] 8e fb [2] b1 e7 }

  condition:
    any of them
}