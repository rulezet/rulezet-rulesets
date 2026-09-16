rule TTP_XOR_WriteProcessMemory_67bc {
  strings:
    $key_67bc = { 30 ce [2] 02 ec [2] 04 d9 [2] 2a d9 [2] 15 c5 }

  condition:
    any of them
}