rule TTP_XOR_WriteProcessMemory_e7bc {
  strings:
    $key_e7bc = { b0 ce [2] 82 ec [2] 84 d9 [2] aa d9 [2] 95 c5 }

  condition:
    any of them
}