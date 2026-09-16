rule TTP_XOR_WriteProcessMemory_de43 {
  strings:
    $key_de43 = { 89 31 [2] bb 13 [2] bd 26 [2] 93 26 [2] ac 3a }

  condition:
    any of them
}