rule TTP_XOR_WriteProcessMemory_9742 {
  strings:
    $key_9742 = { c0 30 [2] f2 12 [2] f4 27 [2] da 27 [2] e5 3b }

  condition:
    any of them
}