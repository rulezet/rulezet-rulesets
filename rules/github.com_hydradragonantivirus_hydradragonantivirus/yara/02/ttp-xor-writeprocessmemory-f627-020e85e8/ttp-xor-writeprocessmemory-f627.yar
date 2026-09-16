rule TTP_XOR_WriteProcessMemory_f627 {
  strings:
    $key_f627 = { a1 55 [2] 93 77 [2] 95 42 [2] bb 42 [2] 84 5e }

  condition:
    any of them
}