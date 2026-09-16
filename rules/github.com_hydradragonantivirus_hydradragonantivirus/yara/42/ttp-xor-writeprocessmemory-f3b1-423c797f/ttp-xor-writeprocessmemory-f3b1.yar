rule TTP_XOR_WriteProcessMemory_f3b1 {
  strings:
    $key_f3b1 = { a4 c3 [2] 96 e1 [2] 90 d4 [2] be d4 [2] 81 c8 }

  condition:
    any of them
}