rule TTP_XOR_WriteProcessMemory_de71 {
  strings:
    $key_de71 = { 89 03 [2] bb 21 [2] bd 14 [2] 93 14 [2] ac 08 }

  condition:
    any of them
}