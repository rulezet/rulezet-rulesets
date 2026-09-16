rule TTP_XOR_WriteProcessMemory_cdb7 {
  strings:
    $key_cdb7 = { 9a c5 [2] a8 e7 [2] ae d2 [2] 80 d2 [2] bf ce }

  condition:
    any of them
}