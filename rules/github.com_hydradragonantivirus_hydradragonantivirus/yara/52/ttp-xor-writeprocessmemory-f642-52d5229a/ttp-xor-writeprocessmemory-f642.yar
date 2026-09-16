rule TTP_XOR_WriteProcessMemory_f642 {
  strings:
    $key_f642 = { a1 30 [2] 93 12 [2] 95 27 [2] bb 27 [2] 84 3b }

  condition:
    any of them
}