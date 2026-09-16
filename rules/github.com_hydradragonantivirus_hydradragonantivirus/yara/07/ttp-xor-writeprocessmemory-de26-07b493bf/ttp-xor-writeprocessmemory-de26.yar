rule TTP_XOR_WriteProcessMemory_de26 {
  strings:
    $key_de26 = { 89 54 [2] bb 76 [2] bd 43 [2] 93 43 [2] ac 5f }

  condition:
    any of them
}