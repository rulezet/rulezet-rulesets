rule TTP_XOR_WriteProcessMemory_4625 {
  strings:
    $key_4625 = { 11 57 [2] 23 75 [2] 25 40 [2] 0b 40 [2] 34 5c }

  condition:
    any of them
}