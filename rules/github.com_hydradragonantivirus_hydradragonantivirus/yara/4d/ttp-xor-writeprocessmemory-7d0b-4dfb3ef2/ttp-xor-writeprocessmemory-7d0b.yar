rule TTP_XOR_WriteProcessMemory_7d0b {
  strings:
    $key_7d0b = { 2a 79 [2] 18 5b [2] 1e 6e [2] 30 6e [2] 0f 72 }

  condition:
    any of them
}