rule TTP_XOR_WriteProcessMemory_34b7 {
  strings:
    $key_34b7 = { 63 c5 [2] 51 e7 [2] 57 d2 [2] 79 d2 [2] 46 ce }

  condition:
    any of them
}