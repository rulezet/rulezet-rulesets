rule TTP_XOR_WriteProcessMemory_de3d {
  strings:
    $key_de3d = { 89 4f [2] bb 6d [2] bd 58 [2] 93 58 [2] ac 44 }

  condition:
    any of them
}