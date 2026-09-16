rule TTP_XOR_WriteProcessMemory_97b7 {
  strings:
    $key_97b7 = { c0 c5 [2] f2 e7 [2] f4 d2 [2] da d2 [2] e5 ce }

  condition:
    any of them
}