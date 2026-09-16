rule TTP_XOR_WriteProcessMemory_9792 {
  strings:
    $key_9792 = { c0 e0 [2] f2 c2 [2] f4 f7 [2] da f7 [2] e5 eb }

  condition:
    any of them
}