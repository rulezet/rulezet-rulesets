rule TTP_XOR_WriteProcessMemory_01b7 {
  strings:
    $key_01b7 = { 56 c5 [2] 64 e7 [2] 62 d2 [2] 4c d2 [2] 73 ce }

  condition:
    any of them
}