rule TTP_XOR_WriteProcessMemory_92d2 {
  strings:
    $key_92d2 = { c5 a0 [2] f7 82 [2] f1 b7 [2] df b7 [2] e0 ab }

  condition:
    any of them
}