rule TTP_XOR_WriteProcessMemory_42bc {
  strings:
    $key_42bc = { 15 ce [2] 27 ec [2] 21 d9 [2] 0f d9 [2] 30 c5 }

  condition:
    any of them
}