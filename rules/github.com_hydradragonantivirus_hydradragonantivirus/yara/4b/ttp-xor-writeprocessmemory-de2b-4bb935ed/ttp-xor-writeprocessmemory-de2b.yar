rule TTP_XOR_WriteProcessMemory_de2b {
  strings:
    $key_de2b = { 89 59 [2] bb 7b [2] bd 4e [2] 93 4e [2] ac 52 }

  condition:
    any of them
}