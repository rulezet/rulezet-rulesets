rule TTP_XOR_WriteProcessMemory_f621 {
  strings:
    $key_f621 = { a1 53 [2] 93 71 [2] 95 44 [2] bb 44 [2] 84 58 }

  condition:
    any of them
}