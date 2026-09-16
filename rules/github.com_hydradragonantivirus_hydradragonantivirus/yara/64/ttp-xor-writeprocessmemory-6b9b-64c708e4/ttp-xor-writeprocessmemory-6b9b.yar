rule TTP_XOR_WriteProcessMemory_6b9b {
  strings:
    $key_6b9b = { 3c e9 [2] 0e cb [2] 08 fe [2] 26 fe [2] 19 e2 }

  condition:
    any of them
}