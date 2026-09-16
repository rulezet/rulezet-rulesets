rule TTP_XOR_WriteProcessMemory_de07 {
  strings:
    $key_de07 = { 89 75 [2] bb 57 [2] bd 62 [2] 93 62 [2] ac 7e }

  condition:
    any of them
}