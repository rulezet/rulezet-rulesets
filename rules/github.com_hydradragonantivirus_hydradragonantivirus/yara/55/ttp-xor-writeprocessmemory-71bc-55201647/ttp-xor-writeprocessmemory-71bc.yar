rule TTP_XOR_WriteProcessMemory_71bc {
  strings:
    $key_71bc = { 26 ce [2] 14 ec [2] 12 d9 [2] 3c d9 [2] 03 c5 }

  condition:
    any of them
}