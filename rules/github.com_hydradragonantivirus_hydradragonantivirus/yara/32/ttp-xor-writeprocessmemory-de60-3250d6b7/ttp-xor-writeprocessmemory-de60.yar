rule TTP_XOR_WriteProcessMemory_de60 {
  strings:
    $key_de60 = { 89 12 [2] bb 30 [2] bd 05 [2] 93 05 [2] ac 19 }

  condition:
    any of them
}