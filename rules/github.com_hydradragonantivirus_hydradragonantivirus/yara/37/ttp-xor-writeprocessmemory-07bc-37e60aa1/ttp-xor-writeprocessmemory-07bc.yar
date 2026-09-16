rule TTP_XOR_WriteProcessMemory_07bc {
  strings:
    $key_07bc = { 50 ce [2] 62 ec [2] 64 d9 [2] 4a d9 [2] 75 c5 }

  condition:
    any of them
}