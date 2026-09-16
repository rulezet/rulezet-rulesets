rule TTP_XOR_WriteProcessMemory_9279 {
  strings:
    $key_9279 = { c5 0b [2] f7 29 [2] f1 1c [2] df 1c [2] e0 00 }

  condition:
    any of them
}