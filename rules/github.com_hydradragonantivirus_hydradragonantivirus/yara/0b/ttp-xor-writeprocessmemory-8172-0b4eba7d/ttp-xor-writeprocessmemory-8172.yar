rule TTP_XOR_WriteProcessMemory_8172 {
  strings:
    $key_8172 = { d6 00 [2] e4 22 [2] e2 17 [2] cc 17 [2] f3 0b }

  condition:
    any of them
}