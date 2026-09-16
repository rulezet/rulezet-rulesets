rule TTP_XOR_WriteProcessMemory_09b7 {
  strings:
    $key_09b7 = { 5e c5 [2] 6c e7 [2] 6a d2 [2] 44 d2 [2] 7b ce }

  condition:
    any of them
}