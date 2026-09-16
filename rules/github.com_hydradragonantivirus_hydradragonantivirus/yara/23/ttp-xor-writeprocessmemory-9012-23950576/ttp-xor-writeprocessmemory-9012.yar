rule TTP_XOR_WriteProcessMemory_9012 {
  strings:
    $key_9012 = { c7 60 [2] f5 42 [2] f3 77 [2] dd 77 [2] e2 6b }

  condition:
    any of them
}