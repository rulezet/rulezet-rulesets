rule TTP_XOR_WriteProcessMemory_45bc {
  strings:
    $key_45bc = { 12 ce [2] 20 ec [2] 26 d9 [2] 08 d9 [2] 37 c5 }

  condition:
    any of them
}