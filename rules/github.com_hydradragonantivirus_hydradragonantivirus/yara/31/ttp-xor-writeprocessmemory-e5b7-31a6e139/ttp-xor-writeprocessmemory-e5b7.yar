rule TTP_XOR_WriteProcessMemory_e5b7 {
  strings:
    $key_e5b7 = { b2 c5 [2] 80 e7 [2] 86 d2 [2] a8 d2 [2] 97 ce }

  condition:
    any of them
}