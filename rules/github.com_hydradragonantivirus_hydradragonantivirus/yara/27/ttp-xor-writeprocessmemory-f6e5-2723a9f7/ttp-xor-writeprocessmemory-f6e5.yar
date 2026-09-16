rule TTP_XOR_WriteProcessMemory_f6e5 {
  strings:
    $key_f6e5 = { a1 97 [2] 93 b5 [2] 95 80 [2] bb 80 [2] 84 9c }

  condition:
    any of them
}