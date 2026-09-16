rule TTP_XOR_WriteProcessMemory_de34 {
  strings:
    $key_de34 = { 89 46 [2] bb 64 [2] bd 51 [2] 93 51 [2] ac 4d }

  condition:
    any of them
}