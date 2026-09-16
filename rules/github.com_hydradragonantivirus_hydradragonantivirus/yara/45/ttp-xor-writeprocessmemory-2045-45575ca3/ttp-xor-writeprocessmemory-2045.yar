rule TTP_XOR_WriteProcessMemory_2045 {
  strings:
    $key_2045 = { 77 37 [2] 45 15 [2] 43 20 [2] 6d 20 [2] 52 3c }

  condition:
    any of them
}