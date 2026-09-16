rule TTP_XOR_WriteProcessMemory_f205 {
  strings:
    $key_f205 = { a5 77 [2] 97 55 [2] 91 60 [2] bf 60 [2] 80 7c }

  condition:
    any of them
}