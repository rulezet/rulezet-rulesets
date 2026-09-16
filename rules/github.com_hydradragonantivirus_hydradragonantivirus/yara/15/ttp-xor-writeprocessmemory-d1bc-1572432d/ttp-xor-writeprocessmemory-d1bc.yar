rule TTP_XOR_WriteProcessMemory_d1bc {
  strings:
    $key_d1bc = { 86 ce [2] b4 ec [2] b2 d9 [2] 9c d9 [2] a3 c5 }

  condition:
    any of them
}