rule TTP_XOR_WriteProcessMemory_02bc {
  strings:
    $key_02bc = { 55 ce [2] 67 ec [2] 61 d9 [2] 4f d9 [2] 70 c5 }

  condition:
    any of them
}