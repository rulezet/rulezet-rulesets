rule TTP_XOR_WriteProcessMemory_e9ab {
  strings:
    $key_e9ab = { be d9 [2] 8c fb [2] 8a ce [2] a4 ce [2] 9b d2 }

  condition:
    any of them
}