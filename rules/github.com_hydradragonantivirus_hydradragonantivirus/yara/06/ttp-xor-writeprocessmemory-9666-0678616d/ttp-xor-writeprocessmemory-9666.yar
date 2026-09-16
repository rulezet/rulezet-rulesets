rule TTP_XOR_WriteProcessMemory_9666 {
  strings:
    $key_9666 = { c1 14 [2] f3 36 [2] f5 03 [2] db 03 [2] e4 1f }

  condition:
    any of them
}