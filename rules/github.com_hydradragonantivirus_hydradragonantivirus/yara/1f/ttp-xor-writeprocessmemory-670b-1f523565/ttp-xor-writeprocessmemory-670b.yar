rule TTP_XOR_WriteProcessMemory_670b {
  strings:
    $key_670b = { 30 79 [2] 02 5b [2] 04 6e [2] 2a 6e [2] 15 72 }

  condition:
    any of them
}