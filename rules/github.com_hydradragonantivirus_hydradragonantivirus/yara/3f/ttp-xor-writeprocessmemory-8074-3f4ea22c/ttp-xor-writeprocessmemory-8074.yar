rule TTP_XOR_WriteProcessMemory_8074 {
  strings:
    $key_8074 = { d7 06 [2] e5 24 [2] e3 11 [2] cd 11 [2] f2 0d }

  condition:
    any of them
}