rule TTP_XOR_WriteProcessMemory_30ab {
  strings:
    $key_30ab = { 67 d9 [2] 55 fb [2] 53 ce [2] 7d ce [2] 42 d2 }

  condition:
    any of them
}