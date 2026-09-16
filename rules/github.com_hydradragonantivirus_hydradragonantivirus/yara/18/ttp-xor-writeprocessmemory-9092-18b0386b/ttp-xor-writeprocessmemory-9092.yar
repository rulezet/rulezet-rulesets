rule TTP_XOR_WriteProcessMemory_9092 {
  strings:
    $key_9092 = { c7 e0 [2] f5 c2 [2] f3 f7 [2] dd f7 [2] e2 eb }

  condition:
    any of them
}