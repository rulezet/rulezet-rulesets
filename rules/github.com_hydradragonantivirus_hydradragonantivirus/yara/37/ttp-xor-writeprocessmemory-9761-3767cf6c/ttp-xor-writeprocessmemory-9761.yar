rule TTP_XOR_WriteProcessMemory_9761 {
  strings:
    $key_9761 = { c0 13 [2] f2 31 [2] f4 04 [2] da 04 [2] e5 18 }

  condition:
    any of them
}