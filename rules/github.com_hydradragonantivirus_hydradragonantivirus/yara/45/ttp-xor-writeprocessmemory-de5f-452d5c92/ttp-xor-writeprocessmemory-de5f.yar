rule TTP_XOR_WriteProcessMemory_de5f {
  strings:
    $key_de5f = { 89 2d [2] bb 0f [2] bd 3a [2] 93 3a [2] ac 26 }

  condition:
    any of them
}