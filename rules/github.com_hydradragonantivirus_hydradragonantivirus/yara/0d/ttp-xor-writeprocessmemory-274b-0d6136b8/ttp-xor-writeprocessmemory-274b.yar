rule TTP_XOR_WriteProcessMemory_274b {
  strings:
    $key_274b = { 70 39 [2] 42 1b [2] 44 2e [2] 6a 2e [2] 55 32 }

  condition:
    any of them
}