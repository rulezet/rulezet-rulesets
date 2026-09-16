rule TTP_XOR_WriteProcessMemory_9636 {
  strings:
    $key_9636 = { c1 44 [2] f3 66 [2] f5 53 [2] db 53 [2] e4 4f }

  condition:
    any of them
}