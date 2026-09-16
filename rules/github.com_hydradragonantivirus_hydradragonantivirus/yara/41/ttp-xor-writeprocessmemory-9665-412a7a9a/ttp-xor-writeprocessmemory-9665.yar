rule TTP_XOR_WriteProcessMemory_9665 {
  strings:
    $key_9665 = { c1 17 [2] f3 35 [2] f5 00 [2] db 00 [2] e4 1c }

  condition:
    any of them
}