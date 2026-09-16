rule TTP_XOR_WriteProcessMemory_4195 {
  strings:
    $key_4195 = { 16 e7 [2] 24 c5 [2] 22 f0 [2] 0c f0 [2] 33 ec }

  condition:
    any of them
}