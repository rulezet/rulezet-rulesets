rule TTP_XOR_WriteProcessMemory_1905 {
  strings:
    $key_1905 = { 4e 77 [2] 7c 55 [2] 7a 60 [2] 54 60 [2] 6b 7c }

  condition:
    any of them
}