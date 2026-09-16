rule TTP_XOR_WriteProcessMemory_ecae {
  strings:
    $key_ecae = { bb dc [2] 89 fe [2] 8f cb [2] a1 cb [2] 9e d7 }

  condition:
    any of them
}