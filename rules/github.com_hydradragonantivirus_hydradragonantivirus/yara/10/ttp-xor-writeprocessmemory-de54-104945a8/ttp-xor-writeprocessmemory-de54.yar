rule TTP_XOR_WriteProcessMemory_de54 {
  strings:
    $key_de54 = { 89 26 [2] bb 04 [2] bd 31 [2] 93 31 [2] ac 2d }

  condition:
    any of them
}