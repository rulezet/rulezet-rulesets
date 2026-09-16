rule TTP_XOR_WriteProcessMemory_65bc {
  strings:
    $key_65bc = { 32 ce [2] 00 ec [2] 06 d9 [2] 28 d9 [2] 17 c5 }

  condition:
    any of them
}