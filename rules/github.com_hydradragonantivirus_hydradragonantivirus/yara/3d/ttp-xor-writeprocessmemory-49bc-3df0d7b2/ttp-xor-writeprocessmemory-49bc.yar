rule TTP_XOR_WriteProcessMemory_49bc {
  strings:
    $key_49bc = { 1e ce [2] 2c ec [2] 2a d9 [2] 04 d9 [2] 3b c5 }

  condition:
    any of them
}