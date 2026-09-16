rule TTP_XOR_WriteProcessMemory_8bb7 {
  strings:
    $key_8bb7 = { dc c5 [2] ee e7 [2] e8 d2 [2] c6 d2 [2] f9 ce }

  condition:
    any of them
}