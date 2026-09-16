rule TTP_XOR_WriteProcessMemory_459b {
  strings:
    $key_459b = { 12 e9 [2] 20 cb [2] 26 fe [2] 08 fe [2] 37 e2 }

  condition:
    any of them
}