rule TTP_XOR_WriteProcessMemory_633b {
  strings:
    $key_633b = { 34 49 [2] 06 6b [2] 00 5e [2] 2e 5e [2] 11 42 }

  condition:
    any of them
}