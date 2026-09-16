rule TTP_XOR_WriteProcessMemory_5f95 {
  strings:
    $key_5f95 = { 08 e7 [2] 3a c5 [2] 3c f0 [2] 12 f0 [2] 2d ec }

  condition:
    any of them
}