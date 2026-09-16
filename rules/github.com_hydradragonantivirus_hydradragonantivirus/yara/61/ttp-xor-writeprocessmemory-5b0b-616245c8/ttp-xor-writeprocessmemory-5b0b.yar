rule TTP_XOR_WriteProcessMemory_5b0b {
  strings:
    $key_5b0b = { 0c 79 [2] 3e 5b [2] 38 6e [2] 16 6e [2] 29 72 }

  condition:
    any of them
}