rule TTP_XOR_WriteProcessMemory_9621 {
  strings:
    $key_9621 = { c1 53 [2] f3 71 [2] f5 44 [2] db 44 [2] e4 58 }

  condition:
    any of them
}