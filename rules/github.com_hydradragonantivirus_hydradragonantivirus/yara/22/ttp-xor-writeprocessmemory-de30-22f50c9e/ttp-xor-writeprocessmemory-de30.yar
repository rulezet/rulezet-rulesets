rule TTP_XOR_WriteProcessMemory_de30 {
  strings:
    $key_de30 = { 89 42 [2] bb 60 [2] bd 55 [2] 93 55 [2] ac 49 }

  condition:
    any of them
}