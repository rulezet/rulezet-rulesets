rule TTP_XOR_WriteProcessMemory_9684 {
  strings:
    $key_9684 = { c1 f6 [2] f3 d4 [2] f5 e1 [2] db e1 [2] e4 fd }

  condition:
    any of them
}