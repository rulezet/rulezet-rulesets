rule TTP_XOR_WriteProcessMemory_edb7 {
  strings:
    $key_edb7 = { ba c5 [2] 88 e7 [2] 8e d2 [2] a0 d2 [2] 9f ce }

  condition:
    any of them
}