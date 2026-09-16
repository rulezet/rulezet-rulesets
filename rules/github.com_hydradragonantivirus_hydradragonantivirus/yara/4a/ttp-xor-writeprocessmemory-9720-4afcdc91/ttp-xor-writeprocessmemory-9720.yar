rule TTP_XOR_WriteProcessMemory_9720 {
  strings:
    $key_9720 = { c0 52 [2] f2 70 [2] f4 45 [2] da 45 [2] e5 59 }

  condition:
    any of them
}