rule TTP_XOR_WriteProcessMemory_9603 {
  strings:
    $key_9603 = { c1 71 [2] f3 53 [2] f5 66 [2] db 66 [2] e4 7a }

  condition:
    any of them
}