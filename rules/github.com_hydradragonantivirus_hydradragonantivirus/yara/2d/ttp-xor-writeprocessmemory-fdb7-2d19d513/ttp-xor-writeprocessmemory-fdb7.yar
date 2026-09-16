rule TTP_XOR_WriteProcessMemory_fdb7 {
  strings:
    $key_fdb7 = { aa c5 [2] 98 e7 [2] 9e d2 [2] b0 d2 [2] 8f ce }

  condition:
    any of them
}