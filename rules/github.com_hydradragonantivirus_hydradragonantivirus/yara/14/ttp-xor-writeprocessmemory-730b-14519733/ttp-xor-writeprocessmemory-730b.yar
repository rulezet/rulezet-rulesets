rule TTP_XOR_WriteProcessMemory_730b {
  strings:
    $key_730b = { 24 79 [2] 16 5b [2] 10 6e [2] 3e 6e [2] 01 72 }

  condition:
    any of them
}