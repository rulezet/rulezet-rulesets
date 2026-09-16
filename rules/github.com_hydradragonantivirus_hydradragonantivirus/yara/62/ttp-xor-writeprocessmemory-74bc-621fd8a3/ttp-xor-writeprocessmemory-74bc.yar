rule TTP_XOR_WriteProcessMemory_74bc {
  strings:
    $key_74bc = { 23 ce [2] 11 ec [2] 17 d9 [2] 39 d9 [2] 06 c5 }

  condition:
    any of them
}