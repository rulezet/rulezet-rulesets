rule TTP_XOR_WriteProcessMemory_f66b {
  strings:
    $key_f66b = { a1 19 [2] 93 3b [2] 95 0e [2] bb 0e [2] 84 12 }

  condition:
    any of them
}