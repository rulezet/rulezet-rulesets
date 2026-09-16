rule TTP_XOR_WriteProcessMemory_f295 {
  strings:
    $key_f295 = { a5 e7 [2] 97 c5 [2] 91 f0 [2] bf f0 [2] 80 ec }

  condition:
    any of them
}