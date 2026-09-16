rule TTP_XOR_WriteProcessMemory_3a56 {
  strings:
    $key_3a56 = { 6d 24 [2] 5f 06 [2] 59 33 [2] 77 33 [2] 48 2f }

  condition:
    any of them
}