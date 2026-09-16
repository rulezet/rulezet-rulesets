rule TTP_XOR_WriteProcessMemory_0bab {
  strings:
    $key_0bab = { 5c d9 [2] 6e fb [2] 68 ce [2] 46 ce [2] 79 d2 }

  condition:
    any of them
}