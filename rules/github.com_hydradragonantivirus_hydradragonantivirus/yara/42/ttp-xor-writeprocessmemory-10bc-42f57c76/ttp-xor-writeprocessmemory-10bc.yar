rule TTP_XOR_WriteProcessMemory_10bc {
  strings:
    $key_10bc = { 47 ce [2] 75 ec [2] 73 d9 [2] 5d d9 [2] 62 c5 }

  condition:
    any of them
}