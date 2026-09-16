rule TTP_XOR_WriteProcessMemory_08b7 {
  strings:
    $key_08b7 = { 5f c5 [2] 6d e7 [2] 6b d2 [2] 45 d2 [2] 7a ce }

  condition:
    any of them
}