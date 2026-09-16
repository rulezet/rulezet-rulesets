rule TTP_XOR_WriteProcessMemory_156b {
  strings:
    $key_156b = { 42 19 [2] 70 3b [2] 76 0e [2] 58 0e [2] 67 12 }

  condition:
    any of them
}