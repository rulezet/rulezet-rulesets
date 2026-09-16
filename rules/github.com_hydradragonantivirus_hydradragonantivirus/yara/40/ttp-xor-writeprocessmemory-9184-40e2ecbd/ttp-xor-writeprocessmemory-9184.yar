rule TTP_XOR_WriteProcessMemory_9184 {
  strings:
    $key_9184 = { c6 f6 [2] f4 d4 [2] f2 e1 [2] dc e1 [2] e3 fd }

  condition:
    any of them
}