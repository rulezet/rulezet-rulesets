rule TTP_XOR_WriteProcessMemory_92c7 {
  strings:
    $key_92c7 = { c5 b5 [2] f7 97 [2] f1 a2 [2] df a2 [2] e0 be }

  condition:
    any of them
}