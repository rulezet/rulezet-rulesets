rule TTP_XOR_WriteProcessMemory_9712 {
  strings:
    $key_9712 = { c0 60 [2] f2 42 [2] f4 77 [2] da 77 [2] e5 6b }

  condition:
    any of them
}