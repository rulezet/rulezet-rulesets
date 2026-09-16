rule TTP_XOR_WriteProcessMemory_d0bc {
  strings:
    $key_d0bc = { 87 ce [2] b5 ec [2] b3 d9 [2] 9d d9 [2] a2 c5 }

  condition:
    any of them
}