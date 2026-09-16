rule TTP_XOR_WriteProcessMemory_de20 {
  strings:
    $key_de20 = { 89 52 [2] bb 70 [2] bd 45 [2] 93 45 [2] ac 59 }

  condition:
    any of them
}