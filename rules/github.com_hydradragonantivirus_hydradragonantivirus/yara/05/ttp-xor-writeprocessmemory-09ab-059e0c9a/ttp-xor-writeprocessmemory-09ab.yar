rule TTP_XOR_WriteProcessMemory_09ab {
  strings:
    $key_09ab = { 5e d9 [2] 6c fb [2] 6a ce [2] 44 ce [2] 7b d2 }

  condition:
    any of them
}