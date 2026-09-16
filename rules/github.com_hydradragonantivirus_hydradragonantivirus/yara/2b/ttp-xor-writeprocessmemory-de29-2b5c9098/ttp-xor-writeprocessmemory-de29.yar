rule TTP_XOR_WriteProcessMemory_de29 {
  strings:
    $key_de29 = { 89 5b [2] bb 79 [2] bd 4c [2] 93 4c [2] ac 50 }

  condition:
    any of them
}