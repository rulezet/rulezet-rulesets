rule TTP_XOR_WriteProcessMemory_80d9 {
  strings:
    $key_80d9 = { d7 ab [2] e5 89 [2] e3 bc [2] cd bc [2] f2 a0 }

  condition:
    any of them
}