rule TTP_XOR_WriteProcessMemory_530b {
  strings:
    $key_530b = { 04 79 [2] 36 5b [2] 30 6e [2] 1e 6e [2] 21 72 }

  condition:
    any of them
}