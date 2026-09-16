rule TTP_XOR_WriteProcessMemory_4675 {
  strings:
    $key_4675 = { 11 07 [2] 23 25 [2] 25 10 [2] 0b 10 [2] 34 0c }

  condition:
    any of them
}