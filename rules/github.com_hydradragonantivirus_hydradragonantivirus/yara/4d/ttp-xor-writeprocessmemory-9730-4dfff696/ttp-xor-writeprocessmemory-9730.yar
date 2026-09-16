rule TTP_XOR_WriteProcessMemory_9730 {
  strings:
    $key_9730 = { c0 42 [2] f2 60 [2] f4 55 [2] da 55 [2] e5 49 }

  condition:
    any of them
}