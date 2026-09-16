rule TTP_XOR_WriteProcessMemory_f60b {
  strings:
    $key_f60b = { a1 79 [2] 93 5b [2] 95 6e [2] bb 6e [2] 84 72 }

  condition:
    any of them
}