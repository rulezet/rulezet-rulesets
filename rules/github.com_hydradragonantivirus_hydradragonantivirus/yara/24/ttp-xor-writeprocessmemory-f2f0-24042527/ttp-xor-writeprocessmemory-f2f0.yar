rule TTP_XOR_WriteProcessMemory_f2f0 {
  strings:
    $key_f2f0 = { a5 82 [2] 97 a0 [2] 91 95 [2] bf 95 [2] 80 89 }

  condition:
    any of them
}