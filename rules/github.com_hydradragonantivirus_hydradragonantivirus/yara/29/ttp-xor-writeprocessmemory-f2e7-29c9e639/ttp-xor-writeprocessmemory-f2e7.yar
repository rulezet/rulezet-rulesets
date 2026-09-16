rule TTP_XOR_WriteProcessMemory_f2e7 {
  strings:
    $key_f2e7 = { a5 95 [2] 97 b7 [2] 91 82 [2] bf 82 [2] 80 9e }

  condition:
    any of them
}