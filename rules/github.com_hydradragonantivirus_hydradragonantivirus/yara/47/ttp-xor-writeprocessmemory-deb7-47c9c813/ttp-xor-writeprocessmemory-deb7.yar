rule TTP_XOR_WriteProcessMemory_deb7 {
  strings:
    $key_deb7 = { 89 c5 [2] bb e7 [2] bd d2 [2] 93 d2 [2] ac ce }

  condition:
    any of them
}