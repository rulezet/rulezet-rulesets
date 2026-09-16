rule TTP_XOR_WriteProcessMemory_de31 {
  strings:
    $key_de31 = { 89 43 [2] bb 61 [2] bd 54 [2] 93 54 [2] ac 48 }

  condition:
    any of them
}