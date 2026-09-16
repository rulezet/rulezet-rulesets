rule TTP_XOR_WriteProcessMemory_de3a {
  strings:
    $key_de3a = { 89 48 [2] bb 6a [2] bd 5f [2] 93 5f [2] ac 43 }

  condition:
    any of them
}