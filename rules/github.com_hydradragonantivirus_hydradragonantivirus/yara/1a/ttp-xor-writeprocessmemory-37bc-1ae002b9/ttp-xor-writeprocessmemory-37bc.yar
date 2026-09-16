rule TTP_XOR_WriteProcessMemory_37bc {
  strings:
    $key_37bc = { 60 ce [2] 52 ec [2] 54 d9 [2] 7a d9 [2] 45 c5 }

  condition:
    any of them
}