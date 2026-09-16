rule TTP_XOR_WriteProcessMemory_d69e {
  strings:
    $key_d69e = { 81 ec [2] b3 ce [2] b5 fb [2] 9b fb [2] a4 e7 }

  condition:
    any of them
}