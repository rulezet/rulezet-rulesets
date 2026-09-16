rule TTP_XOR_WriteProcessMemory_9624 {
  strings:
    $key_9624 = { c1 56 [2] f3 74 [2] f5 41 [2] db 41 [2] e4 5d }

  condition:
    any of them
}