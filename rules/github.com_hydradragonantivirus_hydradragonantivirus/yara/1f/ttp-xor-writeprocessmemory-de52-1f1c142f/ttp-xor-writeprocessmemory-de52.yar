rule TTP_XOR_WriteProcessMemory_de52 {
  strings:
    $key_de52 = { 89 20 [2] bb 02 [2] bd 37 [2] 93 37 [2] ac 2b }

  condition:
    any of them
}