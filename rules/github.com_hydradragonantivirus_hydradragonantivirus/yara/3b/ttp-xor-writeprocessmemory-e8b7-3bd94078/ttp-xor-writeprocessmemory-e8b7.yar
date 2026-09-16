rule TTP_XOR_WriteProcessMemory_e8b7 {
  strings:
    $key_e8b7 = { bf c5 [2] 8d e7 [2] 8b d2 [2] a5 d2 [2] 9a ce }

  condition:
    any of them
}