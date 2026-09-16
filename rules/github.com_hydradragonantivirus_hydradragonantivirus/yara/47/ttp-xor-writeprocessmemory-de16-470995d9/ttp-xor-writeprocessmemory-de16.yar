rule TTP_XOR_WriteProcessMemory_de16 {
  strings:
    $key_de16 = { 89 64 [2] bb 46 [2] bd 73 [2] 93 73 [2] ac 6f }

  condition:
    any of them
}