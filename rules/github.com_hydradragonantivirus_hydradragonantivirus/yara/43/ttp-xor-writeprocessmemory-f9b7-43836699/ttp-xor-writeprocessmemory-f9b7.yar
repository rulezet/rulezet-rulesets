rule TTP_XOR_WriteProcessMemory_f9b7 {
  strings:
    $key_f9b7 = { ae c5 [2] 9c e7 [2] 9a d2 [2] b4 d2 [2] 8b ce }

  condition:
    any of them
}