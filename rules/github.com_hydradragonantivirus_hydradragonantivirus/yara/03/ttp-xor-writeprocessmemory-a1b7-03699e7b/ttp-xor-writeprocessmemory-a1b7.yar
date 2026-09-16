rule TTP_XOR_WriteProcessMemory_a1b7 {
  strings:
    $key_a1b7 = { f6 c5 [2] c4 e7 [2] c2 d2 [2] ec d2 [2] d3 ce }

  condition:
    any of them
}