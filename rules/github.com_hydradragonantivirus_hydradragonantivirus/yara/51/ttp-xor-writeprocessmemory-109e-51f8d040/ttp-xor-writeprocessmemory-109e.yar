rule TTP_XOR_WriteProcessMemory_109e {
  strings:
    $key_109e = { 47 ec [2] 75 ce [2] 73 fb [2] 5d fb [2] 62 e7 }

  condition:
    any of them
}