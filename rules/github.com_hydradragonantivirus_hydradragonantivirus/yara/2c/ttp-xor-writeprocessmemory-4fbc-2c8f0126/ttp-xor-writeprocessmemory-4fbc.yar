rule TTP_XOR_WriteProcessMemory_4fbc {
  strings:
    $key_4fbc = { 18 ce [2] 2a ec [2] 2c d9 [2] 02 d9 [2] 3d c5 }

  condition:
    any of them
}