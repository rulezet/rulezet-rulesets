rule TTP_XOR_WriteProcessMemory_bee6 {
  strings:
    $key_bee6 = { e9 94 [2] db b6 [2] dd 83 [2] f3 83 [2] cc 9f }

  condition:
    any of them
}