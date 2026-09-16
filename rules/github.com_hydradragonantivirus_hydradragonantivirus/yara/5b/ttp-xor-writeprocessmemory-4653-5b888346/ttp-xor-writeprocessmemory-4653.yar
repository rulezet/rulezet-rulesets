rule TTP_XOR_WriteProcessMemory_4653 {
  strings:
    $key_4653 = { 11 21 [2] 23 03 [2] 25 36 [2] 0b 36 [2] 34 2a }

  condition:
    any of them
}