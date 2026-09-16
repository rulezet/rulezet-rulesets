rule TTP_XOR_WriteProcessMemory_97f4 {
  strings:
    $key_97f4 = { c0 86 [2] f2 a4 [2] f4 91 [2] da 91 [2] e5 8d }

  condition:
    any of them
}