rule TTP_XOR_WriteProcessMemory_de4a {
  strings:
    $key_de4a = { 89 38 [2] bb 1a [2] bd 2f [2] 93 2f [2] ac 33 }

  condition:
    any of them
}