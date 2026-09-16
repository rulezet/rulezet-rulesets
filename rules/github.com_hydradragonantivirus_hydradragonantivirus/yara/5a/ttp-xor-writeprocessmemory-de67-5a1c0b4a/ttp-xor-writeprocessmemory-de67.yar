rule TTP_XOR_WriteProcessMemory_de67 {
  strings:
    $key_de67 = { 89 15 [2] bb 37 [2] bd 02 [2] 93 02 [2] ac 1e }

  condition:
    any of them
}