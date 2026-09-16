rule TTP_XOR_WriteProcessMemory_f665 {
  strings:
    $key_f665 = { a1 17 [2] 93 35 [2] 95 00 [2] bb 00 [2] 84 1c }

  condition:
    any of them
}