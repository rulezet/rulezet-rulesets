rule TTP_XOR_WriteProcessMemory_de6b {
  strings:
    $key_de6b = { 89 19 [2] bb 3b [2] bd 0e [2] 93 0e [2] ac 12 }

  condition:
    any of them
}