rule TTP_XOR_WriteProcessMemory_6ab7 {
  strings:
    $key_6ab7 = { 3d c5 [2] 0f e7 [2] 09 d2 [2] 27 d2 [2] 18 ce }

  condition:
    any of them
}