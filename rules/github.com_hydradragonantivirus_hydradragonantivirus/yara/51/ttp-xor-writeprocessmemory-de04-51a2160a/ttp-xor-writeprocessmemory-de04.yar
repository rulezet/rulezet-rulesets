rule TTP_XOR_WriteProcessMemory_de04 {
  strings:
    $key_de04 = { 89 76 [2] bb 54 [2] bd 61 [2] 93 61 [2] ac 7d }

  condition:
    any of them
}