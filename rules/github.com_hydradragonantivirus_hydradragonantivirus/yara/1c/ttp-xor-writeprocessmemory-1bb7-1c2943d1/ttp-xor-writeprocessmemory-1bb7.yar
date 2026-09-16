rule TTP_XOR_WriteProcessMemory_1bb7 {
  strings:
    $key_1bb7 = { 4c c5 [2] 7e e7 [2] 78 d2 [2] 56 d2 [2] 69 ce }

  condition:
    any of them
}