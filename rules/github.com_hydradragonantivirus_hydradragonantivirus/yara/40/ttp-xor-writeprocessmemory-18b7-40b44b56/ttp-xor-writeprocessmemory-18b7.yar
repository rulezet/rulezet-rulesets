rule TTP_XOR_WriteProcessMemory_18b7 {
  strings:
    $key_18b7 = { 4f c5 [2] 7d e7 [2] 7b d2 [2] 55 d2 [2] 6a ce }

  condition:
    any of them
}