rule TTP_XOR_WriteProcessMemory_5ab7 {
  strings:
    $key_5ab7 = { 0d c5 [2] 3f e7 [2] 39 d2 [2] 17 d2 [2] 28 ce }

  condition:
    any of them
}