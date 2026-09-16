rule TTP_XOR_WriteProcessMemory_9613 {
  strings:
    $key_9613 = { c1 61 [2] f3 43 [2] f5 76 [2] db 76 [2] e4 6a }

  condition:
    any of them
}