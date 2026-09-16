rule TTP_XOR_WriteProcessMemory_a295 {
  strings:
    $key_a295 = { f5 e7 [2] c7 c5 [2] c1 f0 [2] ef f0 [2] d0 ec }

  condition:
    any of them
}