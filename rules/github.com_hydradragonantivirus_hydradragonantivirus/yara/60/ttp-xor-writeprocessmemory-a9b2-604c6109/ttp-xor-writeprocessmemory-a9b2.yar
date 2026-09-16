rule TTP_XOR_WriteProcessMemory_a9b2 {
  strings:
    $key_a9b2 = { fe c0 [2] cc e2 [2] ca d7 [2] e4 d7 [2] db cb }

  condition:
    any of them
}