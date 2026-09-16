rule TTP_XOR_WriteProcessMemory_1d25 {
  strings:
    $key_1d25 = { 4a 57 [2] 78 75 [2] 7e 40 [2] 50 40 [2] 6f 5c }

  condition:
    any of them
}