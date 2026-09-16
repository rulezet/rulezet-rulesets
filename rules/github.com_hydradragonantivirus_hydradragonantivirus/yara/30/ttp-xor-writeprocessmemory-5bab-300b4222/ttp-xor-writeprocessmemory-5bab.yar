rule TTP_XOR_WriteProcessMemory_5bab {
  strings:
    $key_5bab = { 0c d9 [2] 3e fb [2] 38 ce [2] 16 ce [2] 29 d2 }

  condition:
    any of them
}