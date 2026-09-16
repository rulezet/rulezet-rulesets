rule TTP_XOR_WriteProcessMemory_80a5 {
  strings:
    $key_80a5 = { d7 d7 [2] e5 f5 [2] e3 c0 [2] cd c0 [2] f2 dc }

  condition:
    any of them
}