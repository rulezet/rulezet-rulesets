rule TTP_XOR_WriteProcessMemory_1505 {
  strings:
    $key_1505 = { 42 77 [2] 70 55 [2] 76 60 [2] 58 60 [2] 67 7c }

  condition:
    any of them
}