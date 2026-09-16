rule TTP_XOR_WriteProcessMemory_48b7 {
  strings:
    $key_48b7 = { 1f c5 [2] 2d e7 [2] 2b d2 [2] 05 d2 [2] 3a ce }

  condition:
    any of them
}