rule TTP_XOR_WriteProcessMemory_7fab {
  strings:
    $key_7fab = { 28 d9 [2] 1a fb [2] 1c ce [2] 32 ce [2] 0d d2 }

  condition:
    any of them
}