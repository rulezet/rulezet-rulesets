rule TTP_XOR_WriteProcessMemory_1a9b {
  strings:
    $key_1a9b = { 4d e9 [2] 7f cb [2] 79 fe [2] 57 fe [2] 68 e2 }

  condition:
    any of them
}