rule TTP_XOR_WriteProcessMemory_26bc {
  strings:
    $key_26bc = { 71 ce [2] 43 ec [2] 45 d9 [2] 6b d9 [2] 54 c5 }

  condition:
    any of them
}