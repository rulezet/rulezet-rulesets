rule TTP_XOR_WriteProcessMemory_c2bc {
  strings:
    $key_c2bc = { 95 ce [2] a7 ec [2] a1 d9 [2] 8f d9 [2] b0 c5 }

  condition:
    any of them
}