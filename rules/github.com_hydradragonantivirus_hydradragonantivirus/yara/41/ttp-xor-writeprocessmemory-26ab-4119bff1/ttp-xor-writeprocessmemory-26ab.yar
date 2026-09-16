rule TTP_XOR_WriteProcessMemory_26ab {
  strings:
    $key_26ab = { 71 d9 [2] 43 fb [2] 45 ce [2] 6b ce [2] 54 d2 }

  condition:
    any of them
}