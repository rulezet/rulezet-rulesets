rule TTP_XOR_WriteProcessMemory_630b {
  strings:
    $key_630b = { 34 79 [2] 06 5b [2] 00 6e [2] 2e 6e [2] 11 72 }

  condition:
    any of them
}