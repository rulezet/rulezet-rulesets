rule TTP_XOR_WriteProcessMemory_80d0 {
  strings:
    $key_80d0 = { d7 a2 [2] e5 80 [2] e3 b5 [2] cd b5 [2] f2 a9 }

  condition:
    any of them
}