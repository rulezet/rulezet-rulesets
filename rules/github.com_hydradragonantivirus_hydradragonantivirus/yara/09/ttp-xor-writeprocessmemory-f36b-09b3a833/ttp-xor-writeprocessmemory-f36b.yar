rule TTP_XOR_WriteProcessMemory_f36b {
  strings:
    $key_f36b = { a4 19 [2] 96 3b [2] 90 0e [2] be 0e [2] 81 12 }

  condition:
    any of them
}