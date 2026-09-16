rule TTP_XOR_WriteProcessMemory_9779 {
  strings:
    $key_9779 = { c0 0b [2] f2 29 [2] f4 1c [2] da 1c [2] e5 00 }

  condition:
    any of them
}