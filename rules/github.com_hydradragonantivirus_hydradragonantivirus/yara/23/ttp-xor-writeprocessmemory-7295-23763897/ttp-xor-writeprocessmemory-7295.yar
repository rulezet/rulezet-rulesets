rule TTP_XOR_WriteProcessMemory_7295 {
  strings:
    $key_7295 = { 25 e7 [2] 17 c5 [2] 11 f0 [2] 3f f0 [2] 00 ec }

  condition:
    any of them
}