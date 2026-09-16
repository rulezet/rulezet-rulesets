rule TTP_XOR_WriteProcessMemory_7bb7 {
  strings:
    $key_7bb7 = { 2c c5 [2] 1e e7 [2] 18 d2 [2] 36 d2 [2] 09 ce }

  condition:
    any of them
}