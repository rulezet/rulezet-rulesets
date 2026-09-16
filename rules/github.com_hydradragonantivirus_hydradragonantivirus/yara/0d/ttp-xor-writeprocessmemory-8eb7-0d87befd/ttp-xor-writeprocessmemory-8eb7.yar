rule TTP_XOR_WriteProcessMemory_8eb7 {
  strings:
    $key_8eb7 = { d9 c5 [2] eb e7 [2] ed d2 [2] c3 d2 [2] fc ce }

  condition:
    any of them
}