rule TTP_XOR_WriteProcessMemory_0b9b {
  strings:
    $key_0b9b = { 5c e9 [2] 6e cb [2] 68 fe [2] 46 fe [2] 79 e2 }

  condition:
    any of them
}