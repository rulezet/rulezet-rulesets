rule TTP_XOR_WriteProcessMemory_f2f5 {
  strings:
    $key_f2f5 = { a5 87 [2] 97 a5 [2] 91 90 [2] bf 90 [2] 80 8c }

  condition:
    any of them
}