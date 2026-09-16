rule TTP_XOR_WriteProcessMemory_9626 {
  strings:
    $key_9626 = { c1 54 [2] f3 76 [2] f5 43 [2] db 43 [2] e4 5f }

  condition:
    any of them
}