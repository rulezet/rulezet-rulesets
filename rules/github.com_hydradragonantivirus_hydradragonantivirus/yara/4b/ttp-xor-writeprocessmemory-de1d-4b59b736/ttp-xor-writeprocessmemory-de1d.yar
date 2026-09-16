rule TTP_XOR_WriteProcessMemory_de1d {
  strings:
    $key_de1d = { 89 6f [2] bb 4d [2] bd 78 [2] 93 78 [2] ac 64 }

  condition:
    any of them
}