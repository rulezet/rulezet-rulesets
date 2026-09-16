rule TTP_XOR_WriteProcessMemory_54b7 {
  strings:
    $key_54b7 = { 03 c5 [2] 31 e7 [2] 37 d2 [2] 19 d2 [2] 26 ce }

  condition:
    any of them
}