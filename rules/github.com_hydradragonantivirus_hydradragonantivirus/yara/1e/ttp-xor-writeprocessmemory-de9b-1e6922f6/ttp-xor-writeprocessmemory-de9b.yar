rule TTP_XOR_WriteProcessMemory_de9b {
  strings:
    $key_de9b = { 89 e9 [2] bb cb [2] bd fe [2] 93 fe [2] ac e2 }

  condition:
    any of them
}