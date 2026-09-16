rule TTP_XOR_WriteProcessMemory_f64b {
  strings:
    $key_f64b = { a1 39 [2] 93 1b [2] 95 2e [2] bb 2e [2] 84 32 }

  condition:
    any of them
}