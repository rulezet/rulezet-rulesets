rule TTP_XOR_WriteProcessMemory_f645 {
  strings:
    $key_f645 = { a1 37 [2] 93 15 [2] 95 20 [2] bb 20 [2] 84 3c }

  condition:
    any of them
}