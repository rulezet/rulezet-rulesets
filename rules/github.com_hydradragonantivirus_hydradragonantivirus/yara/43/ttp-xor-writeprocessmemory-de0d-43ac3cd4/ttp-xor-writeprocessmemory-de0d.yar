rule TTP_XOR_WriteProcessMemory_de0d {
  strings:
    $key_de0d = { 89 7f [2] bb 5d [2] bd 68 [2] 93 68 [2] ac 74 }

  condition:
    any of them
}