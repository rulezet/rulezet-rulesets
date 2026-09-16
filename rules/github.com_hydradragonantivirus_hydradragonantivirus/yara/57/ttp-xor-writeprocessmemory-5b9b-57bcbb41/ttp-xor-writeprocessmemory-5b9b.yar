rule TTP_XOR_WriteProcessMemory_5b9b {
  strings:
    $key_5b9b = { 0c e9 [2] 3e cb [2] 38 fe [2] 16 fe [2] 29 e2 }

  condition:
    any of them
}