rule TTP_XOR_WriteProcessMemory_de4f {
  strings:
    $key_de4f = { 89 3d [2] bb 1f [2] bd 2a [2] 93 2a [2] ac 36 }

  condition:
    any of them
}