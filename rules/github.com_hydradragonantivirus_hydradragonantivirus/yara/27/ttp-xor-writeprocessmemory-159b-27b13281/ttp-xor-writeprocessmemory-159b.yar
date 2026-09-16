rule TTP_XOR_WriteProcessMemory_159b {
  strings:
    $key_159b = { 42 e9 [2] 70 cb [2] 76 fe [2] 58 fe [2] 67 e2 }

  condition:
    any of them
}