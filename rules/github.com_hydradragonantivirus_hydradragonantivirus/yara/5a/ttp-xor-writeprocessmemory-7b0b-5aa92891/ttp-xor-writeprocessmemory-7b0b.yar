rule TTP_XOR_WriteProcessMemory_7b0b {
  strings:
    $key_7b0b = { 2c 79 [2] 1e 5b [2] 18 6e [2] 36 6e [2] 09 72 }

  condition:
    any of them
}