rule TTP_XOR_WriteProcessMemory_6295 {
  strings:
    $key_6295 = { 35 e7 [2] 07 c5 [2] 01 f0 [2] 2f f0 [2] 10 ec }

  condition:
    any of them
}