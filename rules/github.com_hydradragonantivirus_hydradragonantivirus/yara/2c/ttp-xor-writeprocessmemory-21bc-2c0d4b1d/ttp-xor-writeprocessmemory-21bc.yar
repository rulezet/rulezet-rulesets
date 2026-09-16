rule TTP_XOR_WriteProcessMemory_21bc {
  strings:
    $key_21bc = { 76 ce [2] 44 ec [2] 42 d9 [2] 6c d9 [2] 53 c5 }

  condition:
    any of them
}