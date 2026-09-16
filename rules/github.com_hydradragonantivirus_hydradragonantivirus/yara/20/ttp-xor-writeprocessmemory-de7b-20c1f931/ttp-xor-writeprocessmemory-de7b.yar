rule TTP_XOR_WriteProcessMemory_de7b {
  strings:
    $key_de7b = { 89 09 [2] bb 2b [2] bd 1e [2] 93 1e [2] ac 02 }

  condition:
    any of them
}