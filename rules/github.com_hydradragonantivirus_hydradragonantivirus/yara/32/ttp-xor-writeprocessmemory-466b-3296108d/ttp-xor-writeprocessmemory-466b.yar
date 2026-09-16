rule TTP_XOR_WriteProcessMemory_466b {
  strings:
    $key_466b = { 11 19 [2] 23 3b [2] 25 0e [2] 0b 0e [2] 34 12 }

  condition:
    any of them
}