rule TTP_XOR_WriteProcessMemory_769e {
  strings:
    $key_769e = { 21 ec [2] 13 ce [2] 15 fb [2] 3b fb [2] 04 e7 }

  condition:
    any of them
}