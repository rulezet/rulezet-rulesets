rule TTP_XOR_WriteProcessMemory_759e {
  strings:
    $key_759e = { 22 ec [2] 10 ce [2] 16 fb [2] 38 fb [2] 07 e7 }

  condition:
    any of them
}