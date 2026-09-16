rule TTP_XOR_WriteProcessMemory_51bc {
  strings:
    $key_51bc = { 06 ce [2] 34 ec [2] 32 d9 [2] 1c d9 [2] 23 c5 }

  condition:
    any of them
}