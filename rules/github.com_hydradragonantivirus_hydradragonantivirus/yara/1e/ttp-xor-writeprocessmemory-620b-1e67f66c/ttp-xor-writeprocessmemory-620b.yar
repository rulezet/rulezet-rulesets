rule TTP_XOR_WriteProcessMemory_620b {
  strings:
    $key_620b = { 35 79 [2] 07 5b [2] 01 6e [2] 2f 6e [2] 10 72 }

  condition:
    any of them
}