rule TTP_XOR_WriteProcessMemory_de46 {
  strings:
    $key_de46 = { 89 34 [2] bb 16 [2] bd 23 [2] 93 23 [2] ac 3f }

  condition:
    any of them
}