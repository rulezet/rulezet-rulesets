rule TTP_XOR_WriteProcessMemory_c895 {
  strings:
    $key_c895 = { 9f e7 [2] ad c5 [2] ab f0 [2] 85 f0 [2] ba ec }

  condition:
    any of them
}