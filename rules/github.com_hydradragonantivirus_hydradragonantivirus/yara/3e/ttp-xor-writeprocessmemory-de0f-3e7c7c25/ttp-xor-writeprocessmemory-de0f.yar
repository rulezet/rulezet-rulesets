rule TTP_XOR_WriteProcessMemory_de0f {
  strings:
    $key_de0f = { 89 7d [2] bb 5f [2] bd 6a [2] 93 6a [2] ac 76 }

  condition:
    any of them
}