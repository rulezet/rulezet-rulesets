rule TTP_XOR_WriteProcessMemory_13bc {
  strings:
    $key_13bc = { 44 ce [2] 76 ec [2] 70 d9 [2] 5e d9 [2] 61 c5 }

  condition:
    any of them
}