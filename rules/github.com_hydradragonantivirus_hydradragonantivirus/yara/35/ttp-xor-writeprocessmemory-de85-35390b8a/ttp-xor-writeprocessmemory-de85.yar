rule TTP_XOR_WriteProcessMemory_de85 {
  strings:
    $key_de85 = { 89 f7 [2] bb d5 [2] bd e0 [2] 93 e0 [2] ac fc }

  condition:
    any of them
}