rule TTP_XOR_WriteProcessMemory_8fb7 {
  strings:
    $key_8fb7 = { d8 c5 [2] ea e7 [2] ec d2 [2] c2 d2 [2] fd ce }

  condition:
    any of them
}