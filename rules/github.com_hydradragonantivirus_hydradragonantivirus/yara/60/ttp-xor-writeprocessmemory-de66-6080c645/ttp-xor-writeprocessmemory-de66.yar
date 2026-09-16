rule TTP_XOR_WriteProcessMemory_de66 {
  strings:
    $key_de66 = { 89 14 [2] bb 36 [2] bd 03 [2] 93 03 [2] ac 1f }

  condition:
    any of them
}