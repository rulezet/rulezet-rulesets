rule TTP_XOR_WriteProcessMemory_c1bc {
  strings:
    $key_c1bc = { 96 ce [2] a4 ec [2] a2 d9 [2] 8c d9 [2] b3 c5 }

  condition:
    any of them
}