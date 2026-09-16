rule TTP_XOR_WriteProcessMemory_de78 {
  strings:
    $key_de78 = { 89 0a [2] bb 28 [2] bd 1d [2] 93 1d [2] ac 01 }

  condition:
    any of them
}