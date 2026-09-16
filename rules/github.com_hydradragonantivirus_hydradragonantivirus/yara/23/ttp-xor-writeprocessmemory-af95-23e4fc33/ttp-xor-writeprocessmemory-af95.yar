rule TTP_XOR_WriteProcessMemory_af95 {
  strings:
    $key_af95 = { f8 e7 [2] ca c5 [2] cc f0 [2] e2 f0 [2] dd ec }

  condition:
    any of them
}