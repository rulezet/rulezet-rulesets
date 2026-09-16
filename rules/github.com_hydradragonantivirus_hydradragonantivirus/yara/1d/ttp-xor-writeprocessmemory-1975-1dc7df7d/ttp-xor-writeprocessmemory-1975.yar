rule TTP_XOR_WriteProcessMemory_1975 {
  strings:
    $key_1975 = { 4e 07 [2] 7c 25 [2] 7a 10 [2] 54 10 [2] 6b 0c }

  condition:
    any of them
}