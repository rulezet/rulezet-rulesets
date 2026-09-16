rule TTP_XOR_WriteProcessMemory_12b7 {
  strings:
    $key_12b7 = { 45 c5 [2] 77 e7 [2] 71 d2 [2] 5f d2 [2] 60 ce }

  condition:
    any of them
}