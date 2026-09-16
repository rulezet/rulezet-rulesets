rule TTP_XOR_WriteProcessMemory_0b6b {
  strings:
    $key_0b6b = { 5c 19 [2] 6e 3b [2] 68 0e [2] 46 0e [2] 79 12 }

  condition:
    any of them
}