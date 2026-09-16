rule TTP_XOR_WriteProcessMemory_b395 {
  strings:
    $key_b395 = { e4 e7 [2] d6 c5 [2] d0 f0 [2] fe f0 [2] c1 ec }

  condition:
    any of them
}