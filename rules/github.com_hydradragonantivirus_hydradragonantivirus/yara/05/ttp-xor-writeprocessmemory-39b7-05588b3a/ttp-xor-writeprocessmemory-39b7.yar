rule TTP_XOR_WriteProcessMemory_39b7 {
  strings:
    $key_39b7 = { 6e c5 [2] 5c e7 [2] 5a d2 [2] 74 d2 [2] 4b ce }

  condition:
    any of them
}