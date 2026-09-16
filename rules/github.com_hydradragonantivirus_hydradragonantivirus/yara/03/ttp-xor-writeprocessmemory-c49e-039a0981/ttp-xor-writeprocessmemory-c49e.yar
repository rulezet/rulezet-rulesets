rule TTP_XOR_WriteProcessMemory_c49e {
  strings:
    $key_c49e = { 93 ec [2] a1 ce [2] a7 fb [2] 89 fb [2] b6 e7 }

  condition:
    any of them
}