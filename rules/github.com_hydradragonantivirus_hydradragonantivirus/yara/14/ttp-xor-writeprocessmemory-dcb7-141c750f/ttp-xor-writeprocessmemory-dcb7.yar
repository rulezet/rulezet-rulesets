rule TTP_XOR_WriteProcessMemory_dcb7 {
  strings:
    $key_dcb7 = { 8b c5 [2] b9 e7 [2] bf d2 [2] 91 d2 [2] ae ce }

  condition:
    any of them
}