rule TTP_XOR_WriteProcessMemory_f3bc {
  strings:
    $key_f3bc = { a4 ce [2] 96 ec [2] 90 d9 [2] be d9 [2] 81 c5 }

  condition:
    any of them
}