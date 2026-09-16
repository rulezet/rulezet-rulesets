rule TTP_XOR_WriteProcessMemory_69ab {
  strings:
    $key_69ab = { 3e d9 [2] 0c fb [2] 0a ce [2] 24 ce [2] 1b d2 }

  condition:
    any of them
}