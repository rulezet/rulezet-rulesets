rule TTP_XOR_WriteProcessMemory_9136 {
  strings:
    $key_9136 = { c6 44 [2] f4 66 [2] f2 53 [2] dc 53 [2] e3 4f }

  condition:
    any of them
}