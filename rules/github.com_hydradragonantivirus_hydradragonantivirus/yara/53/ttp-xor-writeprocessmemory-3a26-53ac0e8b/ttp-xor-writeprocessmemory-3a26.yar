rule TTP_XOR_WriteProcessMemory_3a26 {
  strings:
    $key_3a26 = { 6d 54 [2] 5f 76 [2] 59 43 [2] 77 43 [2] 48 5f }

  condition:
    any of them
}