rule TTP_XOR_WriteProcessMemory_a395 {
  strings:
    $key_a395 = { f4 e7 [2] c6 c5 [2] c0 f0 [2] ee f0 [2] d1 ec }

  condition:
    any of them
}