rule TTP_XOR_WriteProcessMemory_9292 {
  strings:
    $key_9292 = { c5 e0 [2] f7 c2 [2] f1 f7 [2] df f7 [2] e0 eb }

  condition:
    any of them
}