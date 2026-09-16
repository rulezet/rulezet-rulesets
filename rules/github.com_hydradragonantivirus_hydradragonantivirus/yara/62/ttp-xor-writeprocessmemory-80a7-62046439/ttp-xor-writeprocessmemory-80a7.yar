rule TTP_XOR_WriteProcessMemory_80a7 {
  strings:
    $key_80a7 = { d7 d5 [2] e5 f7 [2] e3 c2 [2] cd c2 [2] f2 de }

  condition:
    any of them
}