rule TTP_XOR_WriteProcessMemory_12bc {
  strings:
    $key_12bc = { 45 ce [2] 77 ec [2] 71 d9 [2] 5f d9 [2] 60 c5 }

  condition:
    any of them
}