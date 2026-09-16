rule TTP_XOR_WriteProcessMemory_de28 {
  strings:
    $key_de28 = { 89 5a [2] bb 78 [2] bd 4d [2] 93 4d [2] ac 51 }

  condition:
    any of them
}