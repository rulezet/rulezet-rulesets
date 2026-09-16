rule TTP_XOR_WriteProcessMemory_0bb7 {
  strings:
    $key_0bb7 = { 5c c5 [2] 6e e7 [2] 68 d2 [2] 46 d2 [2] 79 ce }

  condition:
    any of them
}