rule TTP_XOR_WriteProcessMemory_9709 {
  strings:
    $key_9709 = { c0 7b [2] f2 59 [2] f4 6c [2] da 6c [2] e5 70 }

  condition:
    any of them
}