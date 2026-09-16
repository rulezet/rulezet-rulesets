rule TTP_XOR_WriteProcessMemory_97f1 {
  strings:
    $key_97f1 = { c0 83 [2] f2 a1 [2] f4 94 [2] da 94 [2] e5 88 }

  condition:
    any of them
}