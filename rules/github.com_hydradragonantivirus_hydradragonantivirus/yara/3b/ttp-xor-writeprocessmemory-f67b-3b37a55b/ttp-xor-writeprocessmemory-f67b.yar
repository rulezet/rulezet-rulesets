rule TTP_XOR_WriteProcessMemory_f67b {
  strings:
    $key_f67b = { a1 09 [2] 93 2b [2] 95 1e [2] bb 1e [2] 84 02 }

  condition:
    any of them
}