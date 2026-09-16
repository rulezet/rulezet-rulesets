rule TTP_XOR_WriteProcessMemory_84b7 {
  strings:
    $key_84b7 = { d3 c5 [2] e1 e7 [2] e7 d2 [2] c9 d2 [2] f6 ce }

  condition:
    any of them
}