rule TTP_XOR_WriteProcessMemory_1b9b {
  strings:
    $key_1b9b = { 4c e9 [2] 7e cb [2] 78 fe [2] 56 fe [2] 69 e2 }

  condition:
    any of them
}