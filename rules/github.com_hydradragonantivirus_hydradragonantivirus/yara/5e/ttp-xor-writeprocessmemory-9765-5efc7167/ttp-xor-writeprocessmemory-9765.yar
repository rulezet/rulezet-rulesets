rule TTP_XOR_WriteProcessMemory_9765 {
  strings:
    $key_9765 = { c0 17 [2] f2 35 [2] f4 00 [2] da 00 [2] e5 1c }

  condition:
    any of them
}