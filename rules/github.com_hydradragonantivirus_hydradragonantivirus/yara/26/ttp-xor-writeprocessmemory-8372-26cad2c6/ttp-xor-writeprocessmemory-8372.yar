rule TTP_XOR_WriteProcessMemory_8372 {
  strings:
    $key_8372 = { d4 00 [2] e6 22 [2] e0 17 [2] ce 17 [2] f1 0b }

  condition:
    any of them
}