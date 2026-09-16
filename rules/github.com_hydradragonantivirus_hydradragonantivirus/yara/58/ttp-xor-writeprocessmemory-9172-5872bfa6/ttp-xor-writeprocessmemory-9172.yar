rule TTP_XOR_WriteProcessMemory_9172 {
  strings:
    $key_9172 = { c6 00 [2] f4 22 [2] f2 17 [2] dc 17 [2] e3 0b }

  condition:
    any of them
}