rule TTP_XOR_WriteProcessMemory_1705 {
  strings:
    $key_1705 = { 40 77 [2] 72 55 [2] 74 60 [2] 5a 60 [2] 65 7c }

  condition:
    any of them
}