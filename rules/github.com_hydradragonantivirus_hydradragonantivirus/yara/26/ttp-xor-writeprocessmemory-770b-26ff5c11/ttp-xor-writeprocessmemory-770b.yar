rule TTP_XOR_WriteProcessMemory_770b {
  strings:
    $key_770b = { 20 79 [2] 12 5b [2] 14 6e [2] 3a 6e [2] 05 72 }

  condition:
    any of them
}