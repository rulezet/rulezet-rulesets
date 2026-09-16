rule TTP_XOR_WriteProcessMemory_f64c {
  strings:
    $key_f64c = { a1 3e [2] 93 1c [2] 95 29 [2] bb 29 [2] 84 35 }

  condition:
    any of them
}