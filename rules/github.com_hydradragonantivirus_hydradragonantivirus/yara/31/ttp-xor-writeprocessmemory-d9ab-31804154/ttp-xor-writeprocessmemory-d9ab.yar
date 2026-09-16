rule TTP_XOR_WriteProcessMemory_d9ab {
  strings:
    $key_d9ab = { 8e d9 [2] bc fb [2] ba ce [2] 94 ce [2] ab d2 }

  condition:
    any of them
}