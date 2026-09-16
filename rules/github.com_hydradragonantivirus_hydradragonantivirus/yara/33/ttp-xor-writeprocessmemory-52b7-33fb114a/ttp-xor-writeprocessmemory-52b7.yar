rule TTP_XOR_WriteProcessMemory_52b7 {
  strings:
    $key_52b7 = { 05 c5 [2] 37 e7 [2] 31 d2 [2] 1f d2 [2] 20 ce }

  condition:
    any of them
}