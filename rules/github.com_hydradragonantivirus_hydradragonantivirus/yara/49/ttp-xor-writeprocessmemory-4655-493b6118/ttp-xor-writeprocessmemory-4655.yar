rule TTP_XOR_WriteProcessMemory_4655 {
  strings:
    $key_4655 = { 11 27 [2] 23 05 [2] 25 30 [2] 0b 30 [2] 34 2c }

  condition:
    any of them
}