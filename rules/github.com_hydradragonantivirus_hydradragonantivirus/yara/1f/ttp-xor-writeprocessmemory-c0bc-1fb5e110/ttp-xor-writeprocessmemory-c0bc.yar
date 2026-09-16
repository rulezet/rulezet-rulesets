rule TTP_XOR_WriteProcessMemory_c0bc {
  strings:
    $key_c0bc = { 97 ce [2] a5 ec [2] a3 d9 [2] 8d d9 [2] b2 c5 }

  condition:
    any of them
}