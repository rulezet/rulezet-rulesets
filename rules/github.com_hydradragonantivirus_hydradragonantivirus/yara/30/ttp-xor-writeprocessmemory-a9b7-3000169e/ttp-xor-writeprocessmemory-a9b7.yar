rule TTP_XOR_WriteProcessMemory_a9b7 {
  strings:
    $key_a9b7 = { fe c5 [2] cc e7 [2] ca d2 [2] e4 d2 [2] db ce }

  condition:
    any of them
}