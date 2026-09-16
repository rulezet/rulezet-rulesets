rule TTP_XOR_WriteProcessMemory_5c0b {
  strings:
    $key_5c0b = { 0b 79 [2] 39 5b [2] 3f 6e [2] 11 6e [2] 2e 72 }

  condition:
    any of them
}