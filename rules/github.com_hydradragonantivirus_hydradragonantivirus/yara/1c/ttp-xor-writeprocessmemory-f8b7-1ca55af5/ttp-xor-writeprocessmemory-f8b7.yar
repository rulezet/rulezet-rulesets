rule TTP_XOR_WriteProcessMemory_f8b7 {
  strings:
    $key_f8b7 = { af c5 [2] 9d e7 [2] 9b d2 [2] b5 d2 [2] 8a ce }

  condition:
    any of them
}