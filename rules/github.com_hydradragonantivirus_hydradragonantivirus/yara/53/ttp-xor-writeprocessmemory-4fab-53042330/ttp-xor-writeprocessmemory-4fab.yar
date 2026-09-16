rule TTP_XOR_WriteProcessMemory_4fab {
  strings:
    $key_4fab = { 18 d9 [2] 2a fb [2] 2c ce [2] 02 ce [2] 3d d2 }

  condition:
    any of them
}