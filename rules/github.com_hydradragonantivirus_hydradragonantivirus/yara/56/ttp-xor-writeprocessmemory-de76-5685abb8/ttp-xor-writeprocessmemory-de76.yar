rule TTP_XOR_WriteProcessMemory_de76 {
  strings:
    $key_de76 = { 89 04 [2] bb 26 [2] bd 13 [2] 93 13 [2] ac 0f }

  condition:
    any of them
}