rule TTP_XOR_WriteProcessMemory_f648 {
  strings:
    $key_f648 = { a1 3a [2] 93 18 [2] 95 2d [2] bb 2d [2] 84 31 }

  condition:
    any of them
}