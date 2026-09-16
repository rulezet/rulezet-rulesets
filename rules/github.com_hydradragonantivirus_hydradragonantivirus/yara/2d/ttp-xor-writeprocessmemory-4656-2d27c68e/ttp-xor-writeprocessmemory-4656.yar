rule TTP_XOR_WriteProcessMemory_4656 {
  strings:
    $key_4656 = { 11 24 [2] 23 06 [2] 25 33 [2] 0b 33 [2] 34 2f }

  condition:
    any of them
}