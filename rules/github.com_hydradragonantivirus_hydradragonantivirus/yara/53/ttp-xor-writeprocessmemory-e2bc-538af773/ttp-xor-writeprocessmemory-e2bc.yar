rule TTP_XOR_WriteProcessMemory_e2bc {
  strings:
    $key_e2bc = { b5 ce [2] 87 ec [2] 81 d9 [2] af d9 [2] 90 c5 }

  condition:
    any of them
}