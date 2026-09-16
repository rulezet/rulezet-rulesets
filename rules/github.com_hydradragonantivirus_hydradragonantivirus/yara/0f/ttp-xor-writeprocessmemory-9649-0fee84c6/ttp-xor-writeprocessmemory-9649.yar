rule TTP_XOR_WriteProcessMemory_9649 {
  strings:
    $key_9649 = { c1 3b [2] f3 19 [2] f5 2c [2] db 2c [2] e4 30 }

  condition:
    any of them
}