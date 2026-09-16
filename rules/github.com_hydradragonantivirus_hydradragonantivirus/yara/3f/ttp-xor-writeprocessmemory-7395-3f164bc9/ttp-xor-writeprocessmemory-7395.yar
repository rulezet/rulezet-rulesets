rule TTP_XOR_WriteProcessMemory_7395 {
  strings:
    $key_7395 = { 24 e7 [2] 16 c5 [2] 10 f0 [2] 3e f0 [2] 01 ec }

  condition:
    any of them
}