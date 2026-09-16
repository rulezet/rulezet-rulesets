rule TTP_XOR_WriteProcessMemory_9646 {
  strings:
    $key_9646 = { c1 34 [2] f3 16 [2] f5 23 [2] db 23 [2] e4 3f }

  condition:
    any of them
}