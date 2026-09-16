rule TTP_XOR_WriteProcessMemory_5eab {
  strings:
    $key_5eab = { 09 d9 [2] 3b fb [2] 3d ce [2] 13 ce [2] 2c d2 }

  condition:
    any of them
}