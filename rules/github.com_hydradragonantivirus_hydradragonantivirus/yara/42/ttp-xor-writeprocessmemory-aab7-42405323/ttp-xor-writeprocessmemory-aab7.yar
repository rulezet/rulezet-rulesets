rule TTP_XOR_WriteProcessMemory_aab7 {
  strings:
    $key_aab7 = { fd c5 [2] cf e7 [2] c9 d2 [2] e7 d2 [2] d8 ce }

  condition:
    any of them
}