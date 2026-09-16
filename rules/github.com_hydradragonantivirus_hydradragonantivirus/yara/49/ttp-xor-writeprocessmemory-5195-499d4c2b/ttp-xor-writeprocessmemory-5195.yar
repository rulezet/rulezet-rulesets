rule TTP_XOR_WriteProcessMemory_5195 {
  strings:
    $key_5195 = { 06 e7 [2] 34 c5 [2] 32 f0 [2] 1c f0 [2] 23 ec }

  condition:
    any of them
}