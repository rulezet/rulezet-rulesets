rule TTP_XOR_WriteProcessMemory_b5b7 {
  strings:
    $key_b5b7 = { e2 c5 [2] d0 e7 [2] d6 d2 [2] f8 d2 [2] c7 ce }

  condition:
    any of them
}