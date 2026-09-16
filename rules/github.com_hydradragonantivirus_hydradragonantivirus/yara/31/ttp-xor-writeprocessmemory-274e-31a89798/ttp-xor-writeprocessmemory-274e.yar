rule TTP_XOR_WriteProcessMemory_274e {
  strings:
    $key_274e = { 70 3c [2] 42 1e [2] 44 2b [2] 6a 2b [2] 55 37 }

  condition:
    any of them
}