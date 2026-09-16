rule TTP_XOR_WriteProcessMemory_080b {
  strings:
    $key_080b = { 5f 79 [2] 6d 5b [2] 6b 6e [2] 45 6e [2] 7a 72 }

  condition:
    any of them
}