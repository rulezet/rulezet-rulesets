rule TTP_XOR_WriteProcessMemory_9291 {
  strings:
    $key_9291 = { c5 e3 [2] f7 c1 [2] f1 f4 [2] df f4 [2] e0 e8 }

  condition:
    any of them
}