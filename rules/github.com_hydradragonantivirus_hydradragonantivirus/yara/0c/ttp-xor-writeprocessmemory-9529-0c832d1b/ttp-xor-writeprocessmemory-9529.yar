rule TTP_XOR_WriteProcessMemory_9529 {
  strings:
    $key_9529 = { c2 5b [2] f0 79 [2] f6 4c [2] d8 4c [2] e7 50 }

  condition:
    any of them
}