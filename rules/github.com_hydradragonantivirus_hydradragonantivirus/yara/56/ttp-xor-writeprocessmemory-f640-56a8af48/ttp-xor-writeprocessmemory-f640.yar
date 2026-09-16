rule TTP_XOR_WriteProcessMemory_f640 {
  strings:
    $key_f640 = { a1 32 [2] 93 10 [2] 95 25 [2] bb 25 [2] 84 39 }

  condition:
    any of them
}