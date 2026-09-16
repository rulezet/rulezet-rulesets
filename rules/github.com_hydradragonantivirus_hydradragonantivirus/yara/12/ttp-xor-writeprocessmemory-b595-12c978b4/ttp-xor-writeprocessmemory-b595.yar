rule TTP_XOR_WriteProcessMemory_b595 {
  strings:
    $key_b595 = { e2 e7 [2] d0 c5 [2] d6 f0 [2] f8 f0 [2] c7 ec }

  condition:
    any of them
}