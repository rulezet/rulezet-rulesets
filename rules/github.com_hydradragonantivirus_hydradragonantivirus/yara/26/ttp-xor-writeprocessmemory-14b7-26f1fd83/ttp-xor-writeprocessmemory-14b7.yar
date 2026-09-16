rule TTP_XOR_WriteProcessMemory_14b7 {
  strings:
    $key_14b7 = { 43 c5 [2] 71 e7 [2] 77 d2 [2] 59 d2 [2] 66 ce }

  condition:
    any of them
}