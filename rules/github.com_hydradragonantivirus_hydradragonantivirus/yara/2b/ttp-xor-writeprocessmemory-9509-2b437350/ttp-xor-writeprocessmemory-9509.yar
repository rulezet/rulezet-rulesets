rule TTP_XOR_WriteProcessMemory_9509 {
  strings:
    $key_9509 = { c2 7b [2] f0 59 [2] f6 6c [2] d8 6c [2] e7 70 }

  condition:
    any of them
}