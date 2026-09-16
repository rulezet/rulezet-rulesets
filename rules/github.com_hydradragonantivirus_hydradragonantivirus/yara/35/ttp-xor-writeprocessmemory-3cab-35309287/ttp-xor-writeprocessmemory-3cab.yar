rule TTP_XOR_WriteProcessMemory_3cab {
  strings:
    $key_3cab = { 6b d9 [2] 59 fb [2] 5f ce [2] 71 ce [2] 4e d2 }

  condition:
    any of them
}