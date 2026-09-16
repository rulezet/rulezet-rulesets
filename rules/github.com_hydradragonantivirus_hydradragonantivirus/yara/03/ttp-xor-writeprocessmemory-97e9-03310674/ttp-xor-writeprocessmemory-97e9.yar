rule TTP_XOR_WriteProcessMemory_97e9 {
  strings:
    $key_97e9 = { c0 9b [2] f2 b9 [2] f4 8c [2] da 8c [2] e5 90 }

  condition:
    any of them
}