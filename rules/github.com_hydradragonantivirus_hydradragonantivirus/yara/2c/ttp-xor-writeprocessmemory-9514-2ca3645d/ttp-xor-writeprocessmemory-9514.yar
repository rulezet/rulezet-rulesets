rule TTP_XOR_WriteProcessMemory_9514 {
  strings:
    $key_9514 = { c2 66 [2] f0 44 [2] f6 71 [2] d8 71 [2] e7 6d }

  condition:
    any of them
}