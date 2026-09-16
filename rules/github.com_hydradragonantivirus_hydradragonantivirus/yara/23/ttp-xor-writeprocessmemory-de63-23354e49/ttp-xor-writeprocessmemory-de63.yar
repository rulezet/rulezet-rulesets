rule TTP_XOR_WriteProcessMemory_de63 {
  strings:
    $key_de63 = { 89 11 [2] bb 33 [2] bd 06 [2] 93 06 [2] ac 1a }

  condition:
    any of them
}