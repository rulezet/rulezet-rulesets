rule TTP_XOR_WriteProcessMemory_0fab {
  strings:
    $key_0fab = { 58 d9 [2] 6a fb [2] 6c ce [2] 42 ce [2] 7d d2 }

  condition:
    any of them
}