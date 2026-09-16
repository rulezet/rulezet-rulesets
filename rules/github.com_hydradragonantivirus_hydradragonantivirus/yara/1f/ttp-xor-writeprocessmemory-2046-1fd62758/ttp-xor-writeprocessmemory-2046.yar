rule TTP_XOR_WriteProcessMemory_2046 {
  strings:
    $key_2046 = { 77 34 [2] 45 16 [2] 43 23 [2] 6d 23 [2] 52 3f }

  condition:
    any of them
}