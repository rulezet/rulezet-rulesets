rule TTP_XOR_WriteProcessMemory_9769 {
  strings:
    $key_9769 = { c0 1b [2] f2 39 [2] f4 0c [2] da 0c [2] e5 10 }

  condition:
    any of them
}