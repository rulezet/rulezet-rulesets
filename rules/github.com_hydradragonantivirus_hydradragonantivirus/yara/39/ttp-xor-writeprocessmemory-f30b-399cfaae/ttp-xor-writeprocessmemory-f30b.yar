rule TTP_XOR_WriteProcessMemory_f30b {
  strings:
    $key_f30b = { a4 79 [2] 96 5b [2] 90 6e [2] be 6e [2] 81 72 }

  condition:
    any of them
}