rule TTP_XOR_WriteProcessMemory_de70 {
  strings:
    $key_de70 = { 89 02 [2] bb 20 [2] bd 15 [2] 93 15 [2] ac 09 }

  condition:
    any of them
}