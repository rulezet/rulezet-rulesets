rule TTP_XOR_WriteProcessMemory_f9ab {
  strings:
    $key_f9ab = { ae d9 [2] 9c fb [2] 9a ce [2] b4 ce [2] 8b d2 }

  condition:
    any of them
}