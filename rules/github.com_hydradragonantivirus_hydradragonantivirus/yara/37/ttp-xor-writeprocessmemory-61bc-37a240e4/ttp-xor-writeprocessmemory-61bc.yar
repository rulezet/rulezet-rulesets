rule TTP_XOR_WriteProcessMemory_61bc {
  strings:
    $key_61bc = { 36 ce [2] 04 ec [2] 02 d9 [2] 2c d9 [2] 13 c5 }

  condition:
    any of them
}