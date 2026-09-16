rule TTP_XOR_WriteProcessMemory_f70b {
  strings:
    $key_f70b = { a0 79 [2] 92 5b [2] 94 6e [2] ba 6e [2] 85 72 }

  condition:
    any of them
}