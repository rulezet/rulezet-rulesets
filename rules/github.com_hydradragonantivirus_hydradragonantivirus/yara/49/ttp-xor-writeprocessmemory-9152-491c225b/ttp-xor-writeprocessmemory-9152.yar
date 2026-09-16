rule TTP_XOR_WriteProcessMemory_9152 {
  strings:
    $key_9152 = { c6 20 [2] f4 02 [2] f2 37 [2] dc 37 [2] e3 2b }

  condition:
    any of them
}