rule TTP_XOR_WriteProcessMemory_a695 {
  strings:
    $key_a695 = { f1 e7 [2] c3 c5 [2] c5 f0 [2] eb f0 [2] d4 ec }

  condition:
    any of them
}