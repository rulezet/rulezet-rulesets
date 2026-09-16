rule TTP_XOR_WriteProcessMemory_557b {
  strings:
    $key_557b = { 02 09 [2] 30 2b [2] 36 1e [2] 18 1e [2] 27 02 }

  condition:
    any of them
}