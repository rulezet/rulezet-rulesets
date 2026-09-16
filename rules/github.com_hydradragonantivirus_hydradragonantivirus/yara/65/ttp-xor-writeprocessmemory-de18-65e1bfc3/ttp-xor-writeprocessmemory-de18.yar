rule TTP_XOR_WriteProcessMemory_de18 {
  strings:
    $key_de18 = { 89 6a [2] bb 48 [2] bd 7d [2] 93 7d [2] ac 61 }

  condition:
    any of them
}