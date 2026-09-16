rule TTP_XOR_WriteProcessMemory_4615 {
  strings:
    $key_4615 = { 11 67 [2] 23 45 [2] 25 70 [2] 0b 70 [2] 34 6c }

  condition:
    any of them
}