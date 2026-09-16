rule TTP_XOR_WriteProcessMemory_de2f {
  strings:
    $key_de2f = { 89 5d [2] bb 7f [2] bd 4a [2] 93 4a [2] ac 56 }

  condition:
    any of them
}