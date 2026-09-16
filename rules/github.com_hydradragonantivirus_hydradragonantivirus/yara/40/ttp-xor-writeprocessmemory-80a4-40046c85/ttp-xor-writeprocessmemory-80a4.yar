rule TTP_XOR_WriteProcessMemory_80a4 {
  strings:
    $key_80a4 = { d7 d6 [2] e5 f4 [2] e3 c1 [2] cd c1 [2] f2 dd }

  condition:
    any of them
}