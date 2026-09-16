rule TTP_XOR_WriteProcessMemory_7b9b {
  strings:
    $key_7b9b = { 2c e9 [2] 1e cb [2] 18 fe [2] 36 fe [2] 09 e2 }

  condition:
    any of them
}