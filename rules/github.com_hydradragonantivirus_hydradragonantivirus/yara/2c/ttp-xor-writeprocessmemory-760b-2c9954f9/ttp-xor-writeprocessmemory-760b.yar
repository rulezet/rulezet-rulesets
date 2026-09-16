rule TTP_XOR_WriteProcessMemory_760b {
  strings:
    $key_760b = { 21 79 [2] 13 5b [2] 15 6e [2] 3b 6e [2] 04 72 }

  condition:
    any of them
}