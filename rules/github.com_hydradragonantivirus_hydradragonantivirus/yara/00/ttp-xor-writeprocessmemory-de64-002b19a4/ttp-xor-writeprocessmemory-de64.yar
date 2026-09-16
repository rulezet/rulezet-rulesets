rule TTP_XOR_WriteProcessMemory_de64 {
  strings:
    $key_de64 = { 89 16 [2] bb 34 [2] bd 01 [2] 93 01 [2] ac 1d }

  condition:
    any of them
}