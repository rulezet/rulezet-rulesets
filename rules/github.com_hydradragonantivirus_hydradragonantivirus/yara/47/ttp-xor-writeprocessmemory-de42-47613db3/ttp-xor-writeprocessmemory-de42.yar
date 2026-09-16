rule TTP_XOR_WriteProcessMemory_de42 {
  strings:
    $key_de42 = { 89 30 [2] bb 12 [2] bd 27 [2] 93 27 [2] ac 3b }

  condition:
    any of them
}