rule TTP_XOR_WriteProcessMemory_16bc {
  strings:
    $key_16bc = { 41 ce [2] 73 ec [2] 75 d9 [2] 5b d9 [2] 64 c5 }

  condition:
    any of them
}