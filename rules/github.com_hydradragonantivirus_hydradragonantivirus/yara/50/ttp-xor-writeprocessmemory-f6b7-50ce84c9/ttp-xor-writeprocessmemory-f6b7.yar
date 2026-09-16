rule TTP_XOR_WriteProcessMemory_f6b7 {
  strings:
    $key_f6b7 = { a1 c5 [2] 93 e7 [2] 95 d2 [2] bb d2 [2] 84 ce }

  condition:
    any of them
}