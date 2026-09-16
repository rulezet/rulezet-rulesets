rule TTP_XOR_WriteProcessMemory_f62d {
  strings:
    $key_f62d = { a1 5f [2] 93 7d [2] 95 48 [2] bb 48 [2] 84 54 }

  condition:
    any of them
}