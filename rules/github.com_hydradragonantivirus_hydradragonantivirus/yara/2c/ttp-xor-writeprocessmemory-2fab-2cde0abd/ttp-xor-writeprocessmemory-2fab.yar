rule TTP_XOR_WriteProcessMemory_2fab {
  strings:
    $key_2fab = { 78 d9 [2] 4a fb [2] 4c ce [2] 62 ce [2] 5d d2 }

  condition:
    any of them
}