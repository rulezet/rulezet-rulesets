rule TTP_XOR_WriteProcessMemory_299e {
  strings:
    $key_299e = { 7e ec [2] 4c ce [2] 4a fb [2] 64 fb [2] 5b e7 }

  condition:
    any of them
}