rule TTP_XOR_WriteProcessMemory_276b {
  strings:
    $key_276b = { 70 19 [2] 42 3b [2] 44 0e [2] 6a 0e [2] 55 12 }

  condition:
    any of them
}