rule TTP_XOR_WriteProcessMemory_9708 {
  strings:
    $key_9708 = { c0 7a [2] f2 58 [2] f4 6d [2] da 6d [2] e5 71 }

  condition:
    any of them
}