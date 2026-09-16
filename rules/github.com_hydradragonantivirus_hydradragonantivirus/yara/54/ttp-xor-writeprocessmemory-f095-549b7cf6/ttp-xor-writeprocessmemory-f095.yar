rule TTP_XOR_WriteProcessMemory_f095 {
  strings:
    $key_f095 = { a7 e7 [2] 95 c5 [2] 93 f0 [2] bd f0 [2] 82 ec }

  condition:
    any of them
}