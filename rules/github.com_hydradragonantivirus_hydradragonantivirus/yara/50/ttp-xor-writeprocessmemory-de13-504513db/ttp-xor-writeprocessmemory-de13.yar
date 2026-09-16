rule TTP_XOR_WriteProcessMemory_de13 {
  strings:
    $key_de13 = { 89 61 [2] bb 43 [2] bd 76 [2] 93 76 [2] ac 6a }

  condition:
    any of them
}