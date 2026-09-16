rule TTP_XOR_WriteProcessMemory_f668 {
  strings:
    $key_f668 = { a1 1a [2] 93 38 [2] 95 0d [2] bb 0d [2] 84 11 }

  condition:
    any of them
}