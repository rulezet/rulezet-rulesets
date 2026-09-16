rule TTP_XOR_WriteProcessMemory_c9ab {
  strings:
    $key_c9ab = { 9e d9 [2] ac fb [2] aa ce [2] 84 ce [2] bb d2 }

  condition:
    any of them
}