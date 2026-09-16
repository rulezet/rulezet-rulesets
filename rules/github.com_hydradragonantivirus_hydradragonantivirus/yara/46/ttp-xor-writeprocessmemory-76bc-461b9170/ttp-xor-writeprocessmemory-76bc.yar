rule TTP_XOR_WriteProcessMemory_76bc {
  strings:
    $key_76bc = { 21 ce [2] 13 ec [2] 15 d9 [2] 3b d9 [2] 04 c5 }

  condition:
    any of them
}