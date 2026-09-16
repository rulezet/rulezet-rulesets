rule TTP_XOR_WriteProcessMemory_9608 {
  strings:
    $key_9608 = { c1 7a [2] f3 58 [2] f5 6d [2] db 6d [2] e4 71 }

  condition:
    any of them
}