rule TTP_XOR_WriteProcessMemory_8212 {
  strings:
    $key_8212 = { d5 60 [2] e7 42 [2] e1 77 [2] cf 77 [2] f0 6b }

  condition:
    any of them
}