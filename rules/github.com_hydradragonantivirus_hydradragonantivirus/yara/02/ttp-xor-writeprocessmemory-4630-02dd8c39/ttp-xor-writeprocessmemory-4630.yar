rule TTP_XOR_WriteProcessMemory_4630 {
  strings:
    $key_4630 = { 11 42 [2] 23 60 [2] 25 55 [2] 0b 55 [2] 34 49 }

  condition:
    any of them
}