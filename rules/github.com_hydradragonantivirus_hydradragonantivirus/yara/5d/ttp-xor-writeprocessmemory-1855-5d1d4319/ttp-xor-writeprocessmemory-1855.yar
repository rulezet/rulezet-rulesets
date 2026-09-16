rule TTP_XOR_WriteProcessMemory_1855 {
  strings:
    $key_1855 = { 4f 27 [2] 7d 05 [2] 7b 30 [2] 55 30 [2] 6a 2c }

  condition:
    any of them
}