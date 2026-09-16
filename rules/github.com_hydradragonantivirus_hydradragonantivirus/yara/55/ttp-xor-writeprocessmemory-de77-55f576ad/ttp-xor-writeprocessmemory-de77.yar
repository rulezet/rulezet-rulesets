rule TTP_XOR_WriteProcessMemory_de77 {
  strings:
    $key_de77 = { 89 05 [2] bb 27 [2] bd 12 [2] 93 12 [2] ac 0e }

  condition:
    any of them
}