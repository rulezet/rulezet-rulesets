rule TTP_XOR_WriteProcessMemory_9297 {
  strings:
    $key_9297 = { c5 e5 [2] f7 c7 [2] f1 f2 [2] df f2 [2] e0 ee }

  condition:
    any of them
}