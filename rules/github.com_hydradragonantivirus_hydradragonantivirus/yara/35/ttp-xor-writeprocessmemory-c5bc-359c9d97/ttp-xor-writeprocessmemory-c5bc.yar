rule TTP_XOR_WriteProcessMemory_c5bc {
  strings:
    $key_c5bc = { 92 ce [2] a0 ec [2] a6 d9 [2] 88 d9 [2] b7 c5 }

  condition:
    any of them
}