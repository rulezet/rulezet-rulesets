rule TTP_XOR_WriteProcessMemory_f6e1 {
  strings:
    $key_f6e1 = { a1 93 [2] 93 b1 [2] 95 84 [2] bb 84 [2] 84 98 }

  condition:
    any of them
}