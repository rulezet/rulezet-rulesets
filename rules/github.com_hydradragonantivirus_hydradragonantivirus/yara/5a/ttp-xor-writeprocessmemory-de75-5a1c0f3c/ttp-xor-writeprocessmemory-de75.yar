rule TTP_XOR_WriteProcessMemory_de75 {
  strings:
    $key_de75 = { 89 07 [2] bb 25 [2] bd 10 [2] 93 10 [2] ac 0c }

  condition:
    any of them
}