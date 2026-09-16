rule TTP_XOR_WriteProcessMemory_a982 {
  strings:
    $key_a982 = { fe f0 [2] cc d2 [2] ca e7 [2] e4 e7 [2] db fb }

  condition:
    any of them
}