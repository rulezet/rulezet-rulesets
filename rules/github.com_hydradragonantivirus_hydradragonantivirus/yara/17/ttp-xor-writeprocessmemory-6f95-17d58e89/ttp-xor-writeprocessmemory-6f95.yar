rule TTP_XOR_WriteProcessMemory_6f95 {
  strings:
    $key_6f95 = { 38 e7 [2] 0a c5 [2] 0c f0 [2] 22 f0 [2] 1d ec }

  condition:
    any of them
}