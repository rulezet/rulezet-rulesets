rule TTP_XOR_WriteProcessMemory_9173 {
  strings:
    $key_9173 = { c6 01 [2] f4 23 [2] f2 16 [2] dc 16 [2] e3 0a }

  condition:
    any of them
}