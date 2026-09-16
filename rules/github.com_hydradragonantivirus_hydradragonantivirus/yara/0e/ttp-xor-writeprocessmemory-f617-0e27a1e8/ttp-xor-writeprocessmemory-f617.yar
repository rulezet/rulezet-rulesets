rule TTP_XOR_WriteProcessMemory_f617 {
  strings:
    $key_f617 = { a1 65 [2] 93 47 [2] 95 72 [2] bb 72 [2] 84 6e }

  condition:
    any of them
}