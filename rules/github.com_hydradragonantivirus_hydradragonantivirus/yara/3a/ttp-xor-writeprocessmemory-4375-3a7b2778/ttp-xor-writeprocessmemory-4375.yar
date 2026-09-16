rule TTP_XOR_WriteProcessMemory_4375 {
  strings:
    $key_4375 = { 14 07 [2] 26 25 [2] 20 10 [2] 0e 10 [2] 31 0c }

  condition:
    any of them
}