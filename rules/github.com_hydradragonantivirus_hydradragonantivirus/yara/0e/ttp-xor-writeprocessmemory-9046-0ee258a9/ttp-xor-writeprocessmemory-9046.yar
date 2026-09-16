rule TTP_XOR_WriteProcessMemory_9046 {
  strings:
    $key_9046 = { c7 34 [2] f5 16 [2] f3 23 [2] dd 23 [2] e2 3f }

  condition:
    any of them
}