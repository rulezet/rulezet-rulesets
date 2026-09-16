rule TTP_XOR_WriteProcessMemory_f662 {
  strings:
    $key_f662 = { a1 10 [2] 93 32 [2] 95 07 [2] bb 07 [2] 84 1b }

  condition:
    any of them
}