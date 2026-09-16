rule TTP_XOR_WriteProcessMemory_9192 {
  strings:
    $key_9192 = { c6 e0 [2] f4 c2 [2] f2 f7 [2] dc f7 [2] e3 eb }

  condition:
    any of them
}