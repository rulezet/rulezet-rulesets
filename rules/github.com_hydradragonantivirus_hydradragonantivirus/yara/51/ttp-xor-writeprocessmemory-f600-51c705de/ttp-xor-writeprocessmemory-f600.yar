rule TTP_XOR_WriteProcessMemory_f600 {
  strings:
    $key_f600 = { a1 72 [2] 93 50 [2] 95 65 [2] bb 65 [2] 84 79 }

  condition:
    any of them
}