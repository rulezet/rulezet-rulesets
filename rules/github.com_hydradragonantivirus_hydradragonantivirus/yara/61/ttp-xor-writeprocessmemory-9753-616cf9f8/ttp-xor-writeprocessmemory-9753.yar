rule TTP_XOR_WriteProcessMemory_9753 {
  strings:
    $key_9753 = { c0 21 [2] f2 03 [2] f4 36 [2] da 36 [2] e5 2a }

  condition:
    any of them
}