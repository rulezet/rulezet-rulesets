rule TTP_XOR_WriteProcessMemory_f2e1 {
  strings:
    $key_f2e1 = { a5 93 [2] 97 b1 [2] 91 84 [2] bf 84 [2] 80 98 }

  condition:
    any of them
}