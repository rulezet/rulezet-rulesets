rule TTP_XOR_WriteProcessMemory_9290 {
  strings:
    $key_9290 = { c5 e2 [2] f7 c0 [2] f1 f5 [2] df f5 [2] e0 e9 }

  condition:
    any of them
}