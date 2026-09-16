rule TTP_XOR_WriteProcessMemory_cfab {
  strings:
    $key_cfab = { 98 d9 [2] aa fb [2] ac ce [2] 82 ce [2] bd d2 }

  condition:
    any of them
}