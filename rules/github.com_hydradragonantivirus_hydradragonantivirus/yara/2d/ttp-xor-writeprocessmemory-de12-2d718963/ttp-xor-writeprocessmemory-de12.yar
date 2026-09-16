rule TTP_XOR_WriteProcessMemory_de12 {
  strings:
    $key_de12 = { 89 60 [2] bb 42 [2] bd 77 [2] 93 77 [2] ac 6b }

  condition:
    any of them
}