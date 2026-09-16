rule TTP_XOR_WriteProcessMemory_f663 {
  strings:
    $key_f663 = { a1 11 [2] 93 33 [2] 95 06 [2] bb 06 [2] 84 1a }

  condition:
    any of them
}