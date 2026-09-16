rule TTP_XOR_WriteProcessMemory_6bb7 {
  strings:
    $key_6bb7 = { 3c c5 [2] 0e e7 [2] 08 d2 [2] 26 d2 [2] 19 ce }

  condition:
    any of them
}