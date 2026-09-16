rule TTP_XOR_WriteProcessMemory_d2bc {
  strings:
    $key_d2bc = { 85 ce [2] b7 ec [2] b1 d9 [2] 9f d9 [2] a0 c5 }

  condition:
    any of them
}