rule TTP_XOR_WriteProcessMemory_9721 {
  strings:
    $key_9721 = { c0 53 [2] f2 71 [2] f4 44 [2] da 44 [2] e5 58 }

  condition:
    any of them
}