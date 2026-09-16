rule TTP_XOR_WriteProcessMemory_78ab {
  strings:
    $key_78ab = { 2f d9 [2] 1d fb [2] 1b ce [2] 35 ce [2] 0a d2 }

  condition:
    any of them
}