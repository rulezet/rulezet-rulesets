rule TTP_XOR_WriteProcessMemory_1ab7 {
  strings:
    $key_1ab7 = { 4d c5 [2] 7f e7 [2] 79 d2 [2] 57 d2 [2] 68 ce }

  condition:
    any of them
}