rule TTP_XOR_WriteProcessMemory_5f9b {
  strings:
    $key_5f9b = { 08 e9 [2] 3a cb [2] 3c fe [2] 12 fe [2] 2d e2 }

  condition:
    any of them
}