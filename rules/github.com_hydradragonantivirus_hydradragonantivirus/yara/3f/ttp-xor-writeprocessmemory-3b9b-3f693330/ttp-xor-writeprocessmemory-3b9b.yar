rule TTP_XOR_WriteProcessMemory_3b9b {
  strings:
    $key_3b9b = { 6c e9 [2] 5e cb [2] 58 fe [2] 76 fe [2] 49 e2 }

  condition:
    any of them
}