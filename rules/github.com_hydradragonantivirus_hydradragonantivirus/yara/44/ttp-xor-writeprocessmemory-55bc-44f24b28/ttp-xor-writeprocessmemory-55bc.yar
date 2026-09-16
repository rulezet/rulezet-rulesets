rule TTP_XOR_WriteProcessMemory_55bc {
  strings:
    $key_55bc = { 02 ce [2] 30 ec [2] 36 d9 [2] 18 d9 [2] 27 c5 }

  condition:
    any of them
}