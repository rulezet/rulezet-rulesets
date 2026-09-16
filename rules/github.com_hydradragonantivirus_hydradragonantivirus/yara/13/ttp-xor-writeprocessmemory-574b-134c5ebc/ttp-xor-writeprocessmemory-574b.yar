rule TTP_XOR_WriteProcessMemory_574b {
  strings:
    $key_574b = { 00 39 [2] 32 1b [2] 34 2e [2] 1a 2e [2] 25 32 }

  condition:
    any of them
}