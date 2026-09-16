rule TTP_XOR_WriteProcessMemory_589e {
  strings:
    $key_589e = { 0f ec [2] 3d ce [2] 3b fb [2] 15 fb [2] 2a e7 }

  condition:
    any of them
}