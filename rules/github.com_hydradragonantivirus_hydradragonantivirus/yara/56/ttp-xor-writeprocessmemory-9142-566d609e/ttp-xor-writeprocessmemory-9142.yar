rule TTP_XOR_WriteProcessMemory_9142 {
  strings:
    $key_9142 = { c6 30 [2] f4 12 [2] f2 27 [2] dc 27 [2] e3 3b }

  condition:
    any of them
}