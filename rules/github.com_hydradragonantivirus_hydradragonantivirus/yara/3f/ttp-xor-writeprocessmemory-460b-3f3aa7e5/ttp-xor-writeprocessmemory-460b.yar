rule TTP_XOR_WriteProcessMemory_460b {
  strings:
    $key_460b = { 11 79 [2] 23 5b [2] 25 6e [2] 0b 6e [2] 34 72 }

  condition:
    any of them
}