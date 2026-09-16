rule TTP_XOR_WriteProcessMemory_56bc {
  strings:
    $key_56bc = { 01 ce [2] 33 ec [2] 35 d9 [2] 1b d9 [2] 24 c5 }

  condition:
    any of them
}