rule TTP_XOR_WriteProcessMemory_f605 {
  strings:
    $key_f605 = { a1 77 [2] 93 55 [2] 95 60 [2] bb 60 [2] 84 7c }

  condition:
    any of them
}