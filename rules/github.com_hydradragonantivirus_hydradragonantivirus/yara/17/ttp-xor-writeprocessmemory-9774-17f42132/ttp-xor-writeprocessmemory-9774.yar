rule TTP_XOR_WriteProcessMemory_9774 {
  strings:
    $key_9774 = { c0 06 [2] f2 24 [2] f4 11 [2] da 11 [2] e5 0d }

  condition:
    any of them
}