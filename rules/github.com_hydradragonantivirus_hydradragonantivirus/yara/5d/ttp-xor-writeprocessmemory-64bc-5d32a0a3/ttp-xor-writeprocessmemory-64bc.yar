rule TTP_XOR_WriteProcessMemory_64bc {
  strings:
    $key_64bc = { 33 ce [2] 01 ec [2] 07 d9 [2] 29 d9 [2] 16 c5 }

  condition:
    any of them
}