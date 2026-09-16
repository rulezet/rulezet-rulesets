rule TTP_XOR_WriteProcessMemory_92d6 {
  strings:
    $key_92d6 = { c5 a4 [2] f7 86 [2] f1 b3 [2] df b3 [2] e0 af }

  condition:
    any of them
}