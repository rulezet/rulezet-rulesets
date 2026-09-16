rule TTP_XOR_WriteProcessMemory_4623 {
  strings:
    $key_4623 = { 11 51 [2] 23 73 [2] 25 46 [2] 0b 46 [2] 34 5a }

  condition:
    any of them
}