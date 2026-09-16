rule TTP_XOR_WriteProcessMemory_9755 {
  strings:
    $key_9755 = { c0 27 [2] f2 05 [2] f4 30 [2] da 30 [2] e5 2c }

  condition:
    any of them
}