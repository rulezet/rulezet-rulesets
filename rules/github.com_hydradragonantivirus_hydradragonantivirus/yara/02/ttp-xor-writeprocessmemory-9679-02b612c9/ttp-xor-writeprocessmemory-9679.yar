rule TTP_XOR_WriteProcessMemory_9679 {
  strings:
    $key_9679 = { c1 0b [2] f3 29 [2] f5 1c [2] db 1c [2] e4 00 }

  condition:
    any of them
}