rule TTP_XOR_WriteProcessMemory_f62b {
  strings:
    $key_f62b = { a1 59 [2] 93 7b [2] 95 4e [2] bb 4e [2] 84 52 }

  condition:
    any of them
}