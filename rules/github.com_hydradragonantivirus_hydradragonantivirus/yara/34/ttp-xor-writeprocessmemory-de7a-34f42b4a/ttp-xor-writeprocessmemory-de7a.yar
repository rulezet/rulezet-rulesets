rule TTP_XOR_WriteProcessMemory_de7a {
  strings:
    $key_de7a = { 89 08 [2] bb 2a [2] bd 1f [2] 93 1f [2] ac 03 }

  condition:
    any of them
}