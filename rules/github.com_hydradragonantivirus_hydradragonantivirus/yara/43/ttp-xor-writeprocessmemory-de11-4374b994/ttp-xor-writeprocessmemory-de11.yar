rule TTP_XOR_WriteProcessMemory_de11 {
  strings:
    $key_de11 = { 89 63 [2] bb 41 [2] bd 74 [2] 93 74 [2] ac 68 }

  condition:
    any of them
}