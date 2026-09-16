rule TTP_XOR_WriteProcessMemory_6645 {
  strings:
    $key_6645 = { 31 37 [2] 03 15 [2] 05 20 [2] 2b 20 [2] 14 3c }

  condition:
    any of them
}