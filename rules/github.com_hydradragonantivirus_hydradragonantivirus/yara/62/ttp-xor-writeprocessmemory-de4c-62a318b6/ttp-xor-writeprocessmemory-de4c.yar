rule TTP_XOR_WriteProcessMemory_de4c {
  strings:
    $key_de4c = { 89 3e [2] bb 1c [2] bd 29 [2] 93 29 [2] ac 35 }

  condition:
    any of them
}