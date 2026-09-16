rule TTP_XOR_WriteProcessMemory_5bb7 {
  strings:
    $key_5bb7 = { 0c c5 [2] 3e e7 [2] 38 d2 [2] 16 d2 [2] 29 ce }

  condition:
    any of them
}