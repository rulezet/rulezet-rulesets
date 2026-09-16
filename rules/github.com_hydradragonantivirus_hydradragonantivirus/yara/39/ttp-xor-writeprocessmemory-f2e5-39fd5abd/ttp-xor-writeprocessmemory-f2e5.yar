rule TTP_XOR_WriteProcessMemory_f2e5 {
  strings:
    $key_f2e5 = { a5 97 [2] 97 b5 [2] 91 80 [2] bf 80 [2] 80 9c }

  condition:
    any of them
}