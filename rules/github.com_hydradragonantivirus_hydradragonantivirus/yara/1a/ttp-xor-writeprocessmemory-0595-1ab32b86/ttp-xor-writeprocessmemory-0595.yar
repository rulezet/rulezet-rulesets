rule TTP_XOR_WriteProcessMemory_0595 {
  strings:
    $key_0595 = { 52 e7 [2] 60 c5 [2] 66 f0 [2] 48 f0 [2] 77 ec }

  condition:
    any of them
}