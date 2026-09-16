rule TTP_XOR_WriteProcessMemory_97f5 {
  strings:
    $key_97f5 = { c0 87 [2] f2 a5 [2] f4 90 [2] da 90 [2] e5 8c }

  condition:
    any of them
}