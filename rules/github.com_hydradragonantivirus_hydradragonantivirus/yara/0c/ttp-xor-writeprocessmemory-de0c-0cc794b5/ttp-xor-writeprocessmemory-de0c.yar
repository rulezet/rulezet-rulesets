rule TTP_XOR_WriteProcessMemory_de0c {
  strings:
    $key_de0c = { 89 7e [2] bb 5c [2] bd 69 [2] 93 69 [2] ac 75 }

  condition:
    any of them
}