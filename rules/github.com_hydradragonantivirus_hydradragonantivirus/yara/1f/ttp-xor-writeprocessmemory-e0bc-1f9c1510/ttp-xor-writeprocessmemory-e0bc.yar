rule TTP_XOR_WriteProcessMemory_e0bc {
  strings:
    $key_e0bc = { b7 ce [2] 85 ec [2] 83 d9 [2] ad d9 [2] 92 c5 }

  condition:
    any of them
}