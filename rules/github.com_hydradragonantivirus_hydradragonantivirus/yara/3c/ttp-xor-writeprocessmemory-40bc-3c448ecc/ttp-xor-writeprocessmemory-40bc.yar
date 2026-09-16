rule TTP_XOR_WriteProcessMemory_40bc {
  strings:
    $key_40bc = { 17 ce [2] 25 ec [2] 23 d9 [2] 0d d9 [2] 32 c5 }

  condition:
    any of them
}