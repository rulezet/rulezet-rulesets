rule TTP_XOR_WriteProcessMemory_18ab {
  strings:
    $key_18ab = { 4f d9 [2] 7d fb [2] 7b ce [2] 55 ce [2] 6a d2 }

  condition:
    any of them
}