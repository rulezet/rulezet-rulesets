rule TTP_XOR_WriteProcessMemory_4665 {
  strings:
    $key_4665 = { 11 17 [2] 23 35 [2] 25 00 [2] 0b 00 [2] 34 1c }

  condition:
    any of them
}