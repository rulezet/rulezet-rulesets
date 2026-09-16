rule TTP_XOR_WriteProcessMemory_9668 {
  strings:
    $key_9668 = { c1 1a [2] f3 38 [2] f5 0d [2] db 0d [2] e4 11 }

  condition:
    any of them
}