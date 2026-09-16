rule TTP_XOR_WriteProcessMemory_93d2 {
  strings:
    $key_93d2 = { c4 a0 [2] f6 82 [2] f0 b7 [2] de b7 [2] e1 ab }

  condition:
    any of them
}