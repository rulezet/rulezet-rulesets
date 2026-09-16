rule TTP_XOR_WriteProcessMemory_f695 {
  strings:
    $key_f695 = { a1 e7 [2] 93 c5 [2] 95 f0 [2] bb f0 [2] 84 ec }

  condition:
    any of them
}