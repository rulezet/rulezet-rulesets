rule TTP_XOR_WriteProcessMemory_dbb7 {
  strings:
    $key_dbb7 = { 8c c5 [2] be e7 [2] b8 d2 [2] 96 d2 [2] a9 ce }

  condition:
    any of them
}