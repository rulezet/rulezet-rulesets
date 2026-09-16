rule TTP_XOR_WriteProcessMemory_f610 {
  strings:
    $key_f610 = { a1 62 [2] 93 40 [2] 95 75 [2] bb 75 [2] 84 69 }

  condition:
    any of them
}