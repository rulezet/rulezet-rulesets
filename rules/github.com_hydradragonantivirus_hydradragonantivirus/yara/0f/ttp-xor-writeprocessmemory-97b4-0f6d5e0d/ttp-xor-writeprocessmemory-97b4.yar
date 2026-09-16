rule TTP_XOR_WriteProcessMemory_97b4 {
  strings:
    $key_97b4 = { c0 c6 [2] f2 e4 [2] f4 d1 [2] da d1 [2] e5 cd }

  condition:
    any of them
}