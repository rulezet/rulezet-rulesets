rule TTP_XOR_WriteProcessMemory_9770 {
  strings:
    $key_9770 = { c0 02 [2] f2 20 [2] f4 15 [2] da 15 [2] e5 09 }

  condition:
    any of them
}