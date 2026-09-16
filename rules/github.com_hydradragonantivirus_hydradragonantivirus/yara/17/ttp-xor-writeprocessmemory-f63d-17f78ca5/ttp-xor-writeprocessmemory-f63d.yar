rule TTP_XOR_WriteProcessMemory_f63d {
  strings:
    $key_f63d = { a1 4f [2] 93 6d [2] 95 58 [2] bb 58 [2] 84 44 }

  condition:
    any of them
}