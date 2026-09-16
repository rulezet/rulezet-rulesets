rule TTP_XOR_WriteProcessMemory_de8c {
  strings:
    $key_de8c = { 89 fe [2] bb dc [2] bd e9 [2] 93 e9 [2] ac f5 }

  condition:
    any of them
}