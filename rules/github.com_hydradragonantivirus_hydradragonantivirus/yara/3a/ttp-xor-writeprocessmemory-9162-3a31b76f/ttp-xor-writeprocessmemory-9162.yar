rule TTP_XOR_WriteProcessMemory_9162 {
  strings:
    $key_9162 = { c6 10 [2] f4 32 [2] f2 07 [2] dc 07 [2] e3 1b }

  condition:
    any of them
}