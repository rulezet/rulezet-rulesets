rule TTP_XOR_WriteProcessMemory_de41 {
  strings:
    $key_de41 = { 89 33 [2] bb 11 [2] bd 24 [2] 93 24 [2] ac 38 }

  condition:
    any of them
}