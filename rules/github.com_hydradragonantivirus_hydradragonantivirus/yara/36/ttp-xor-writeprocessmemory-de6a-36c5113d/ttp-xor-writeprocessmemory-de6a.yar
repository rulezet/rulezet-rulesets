rule TTP_XOR_WriteProcessMemory_de6a {
  strings:
    $key_de6a = { 89 18 [2] bb 3a [2] bd 0f [2] 93 0f [2] ac 13 }

  condition:
    any of them
}