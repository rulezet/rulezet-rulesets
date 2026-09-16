rule TTP_XOR_WriteProcessMemory_80a6 {
  strings:
    $key_80a6 = { d7 d4 [2] e5 f6 [2] e3 c3 [2] cd c3 [2] f2 df }

  condition:
    any of them
}