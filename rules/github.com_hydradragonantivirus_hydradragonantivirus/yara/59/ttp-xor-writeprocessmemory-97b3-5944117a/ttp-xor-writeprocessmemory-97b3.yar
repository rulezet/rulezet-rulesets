rule TTP_XOR_WriteProcessMemory_97b3 {
  strings:
    $key_97b3 = { c0 c1 [2] f2 e3 [2] f4 d6 [2] da d6 [2] e5 ca }

  condition:
    any of them
}