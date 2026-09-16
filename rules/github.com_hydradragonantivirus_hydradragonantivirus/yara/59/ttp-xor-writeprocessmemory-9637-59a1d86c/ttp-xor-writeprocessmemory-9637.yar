rule TTP_XOR_WriteProcessMemory_9637 {
  strings:
    $key_9637 = { c1 45 [2] f3 67 [2] f5 52 [2] db 52 [2] e4 4e }

  condition:
    any of them
}