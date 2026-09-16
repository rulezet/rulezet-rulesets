rule TTP_XOR_WriteProcessMemory_577b {
  strings:
    $key_577b = { 00 09 [2] 32 2b [2] 34 1e [2] 1a 1e [2] 25 02 }

  condition:
    any of them
}