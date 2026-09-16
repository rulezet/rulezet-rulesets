rule TTP_XOR_WriteProcessMemory_9479 {
  strings:
    $key_9479 = { c3 0b [2] f1 29 [2] f7 1c [2] d9 1c [2] e6 00 }

  condition:
    any of them
}