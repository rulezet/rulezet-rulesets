rule TTP_XOR_WriteProcessMemory_2bb7 {
  strings:
    $key_2bb7 = { 7c c5 [2] 4e e7 [2] 48 d2 [2] 66 d2 [2] 59 ce }

  condition:
    any of them
}