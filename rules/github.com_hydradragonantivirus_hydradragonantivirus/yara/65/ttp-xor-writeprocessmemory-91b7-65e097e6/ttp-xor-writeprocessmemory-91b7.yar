rule TTP_XOR_WriteProcessMemory_91b7 {
  strings:
    $key_91b7 = { c6 c5 [2] f4 e7 [2] f2 d2 [2] dc d2 [2] e3 ce }

  condition:
    any of them
}