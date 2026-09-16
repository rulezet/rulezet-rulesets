rule TTP_XOR_WriteProcessMemory_80d5 {
  strings:
    $key_80d5 = { d7 a7 [2] e5 85 [2] e3 b0 [2] cd b0 [2] f2 ac }

  condition:
    any of them
}