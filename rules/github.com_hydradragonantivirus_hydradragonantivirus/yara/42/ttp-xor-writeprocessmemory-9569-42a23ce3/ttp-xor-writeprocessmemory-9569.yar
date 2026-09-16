rule TTP_XOR_WriteProcessMemory_9569 {
  strings:
    $key_9569 = { c2 1b [2] f0 39 [2] f6 0c [2] d8 0c [2] e7 10 }

  condition:
    any of them
}