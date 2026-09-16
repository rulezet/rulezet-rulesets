rule TTP_XOR_WriteProcessMemory_08ab {
  strings:
    $key_08ab = { 5f d9 [2] 6d fb [2] 6b ce [2] 45 ce [2] 7a d2 }

  condition:
    any of them
}