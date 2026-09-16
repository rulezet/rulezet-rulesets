rule TTP_XOR_WriteProcessMemory_9784 {
  strings:
    $key_9784 = { c0 f6 [2] f2 d4 [2] f4 e1 [2] da e1 [2] e5 fd }

  condition:
    any of them
}