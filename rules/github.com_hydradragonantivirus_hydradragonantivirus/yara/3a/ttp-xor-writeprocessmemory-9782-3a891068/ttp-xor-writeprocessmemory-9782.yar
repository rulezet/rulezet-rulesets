rule TTP_XOR_WriteProcessMemory_9782 {
  strings:
    $key_9782 = { c0 f0 [2] f2 d2 [2] f4 e7 [2] da e7 [2] e5 fb }

  condition:
    any of them
}