rule TTP_XOR_WriteProcessMemory_8495 {
  strings:
    $key_8495 = { d3 e7 [2] e1 c5 [2] e7 f0 [2] c9 f0 [2] f6 ec }

  condition:
    any of them
}