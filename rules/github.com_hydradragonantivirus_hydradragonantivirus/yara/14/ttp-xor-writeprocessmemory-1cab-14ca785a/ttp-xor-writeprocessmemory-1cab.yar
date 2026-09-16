rule TTP_XOR_WriteProcessMemory_1cab {
  strings:
    $key_1cab = { 4b d9 [2] 79 fb [2] 7f ce [2] 51 ce [2] 6e d2 }

  condition:
    any of them
}