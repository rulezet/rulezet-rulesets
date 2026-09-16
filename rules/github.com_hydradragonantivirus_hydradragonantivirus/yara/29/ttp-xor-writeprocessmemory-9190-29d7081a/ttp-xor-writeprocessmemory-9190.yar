rule TTP_XOR_WriteProcessMemory_9190 {
  strings:
    $key_9190 = { c6 e2 [2] f4 c0 [2] f2 f5 [2] dc f5 [2] e3 e9 }

  condition:
    any of them
}