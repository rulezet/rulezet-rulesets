rule TTP_XOR_WriteProcessMemory_9650 {
  strings:
    $key_9650 = { c1 22 [2] f3 00 [2] f5 35 [2] db 35 [2] e4 29 }

  condition:
    any of them
}