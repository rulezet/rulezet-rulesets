rule TTP_XOR_WriteProcessMemory_27bc {
  strings:
    $key_27bc = { 70 ce [2] 42 ec [2] 44 d9 [2] 6a d9 [2] 55 c5 }

  condition:
    any of them
}