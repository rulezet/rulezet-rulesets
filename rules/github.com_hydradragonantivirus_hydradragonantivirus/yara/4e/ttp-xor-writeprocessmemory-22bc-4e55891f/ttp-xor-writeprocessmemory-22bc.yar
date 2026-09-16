rule TTP_XOR_WriteProcessMemory_22bc {
  strings:
    $key_22bc = { 75 ce [2] 47 ec [2] 41 d9 [2] 6f d9 [2] 50 c5 }

  condition:
    any of them
}