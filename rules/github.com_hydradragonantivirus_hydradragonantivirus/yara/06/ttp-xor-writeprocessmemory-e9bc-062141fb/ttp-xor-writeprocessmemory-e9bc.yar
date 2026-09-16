rule TTP_XOR_WriteProcessMemory_e9bc {
  strings:
    $key_e9bc = { be ce [2] 8c ec [2] 8a d9 [2] a4 d9 [2] 9b c5 }

  condition:
    any of them
}