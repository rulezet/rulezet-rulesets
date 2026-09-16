rule TTP_XOR_WriteProcessMemory_9103 {
  strings:
    $key_9103 = { c6 71 [2] f4 53 [2] f2 66 [2] dc 66 [2] e3 7a }

  condition:
    any of them
}