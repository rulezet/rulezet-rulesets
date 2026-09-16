rule TTP_XOR_WriteProcessMemory_9579 {
  strings:
    $key_9579 = { c2 0b [2] f0 29 [2] f6 1c [2] d8 1c [2] e7 00 }

  condition:
    any of them
}