rule TTP_XOR_WriteProcessMemory_9674 {
  strings:
    $key_9674 = { c1 06 [2] f3 24 [2] f5 11 [2] db 11 [2] e4 0d }

  condition:
    any of them
}