rule TTP_XOR_WriteProcessMemory_8295 {
  strings:
    $key_8295 = { d5 e7 [2] e7 c5 [2] e1 f0 [2] cf f0 [2] f0 ec }

  condition:
    any of them
}