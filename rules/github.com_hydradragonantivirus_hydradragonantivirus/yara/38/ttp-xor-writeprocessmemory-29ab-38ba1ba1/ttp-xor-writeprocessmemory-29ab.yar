rule TTP_XOR_WriteProcessMemory_29ab {
  strings:
    $key_29ab = { 7e d9 [2] 4c fb [2] 4a ce [2] 64 ce [2] 5b d2 }

  condition:
    any of them
}