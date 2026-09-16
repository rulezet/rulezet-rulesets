rule TTP_XOR_WriteProcessMemory_de17 {
  strings:
    $key_de17 = { 89 65 [2] bb 47 [2] bd 72 [2] 93 72 [2] ac 6e }

  condition:
    any of them
}