rule TTP_XOR_WriteProcessMemory_de69 {
  strings:
    $key_de69 = { 89 1b [2] bb 39 [2] bd 0c [2] 93 0c [2] ac 10 }

  condition:
    any of them
}