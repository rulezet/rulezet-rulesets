rule TTP_XOR_WriteProcessMemory_de1f {
  strings:
    $key_de1f = { 89 6d [2] bb 4f [2] bd 7a [2] 93 7a [2] ac 66 }

  condition:
    any of them
}