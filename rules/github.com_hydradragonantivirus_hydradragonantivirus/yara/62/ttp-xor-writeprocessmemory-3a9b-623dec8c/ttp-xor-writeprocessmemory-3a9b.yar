rule TTP_XOR_WriteProcessMemory_3a9b {
  strings:
    $key_3a9b = { 6d e9 [2] 5f cb [2] 59 fe [2] 77 fe [2] 48 e2 }

  condition:
    any of them
}