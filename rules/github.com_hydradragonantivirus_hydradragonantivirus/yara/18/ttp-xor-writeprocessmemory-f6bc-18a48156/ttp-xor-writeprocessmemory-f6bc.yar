rule TTP_XOR_WriteProcessMemory_f6bc {
  strings:
    $key_f6bc = { a1 ce [2] 93 ec [2] 95 d9 [2] bb d9 [2] 84 c5 }

  condition:
    any of them
}