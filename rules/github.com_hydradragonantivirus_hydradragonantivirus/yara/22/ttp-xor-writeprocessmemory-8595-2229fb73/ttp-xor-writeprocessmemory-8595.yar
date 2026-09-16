rule TTP_XOR_WriteProcessMemory_8595 {
  strings:
    $key_8595 = { d2 e7 [2] e0 c5 [2] e6 f0 [2] c8 f0 [2] f7 ec }

  condition:
    any of them
}