rule TTP_XOR_WriteProcessMemory_a4b7 {
  strings:
    $key_a4b7 = { f3 c5 [2] c1 e7 [2] c7 d2 [2] e9 d2 [2] d6 ce }

  condition:
    any of them
}