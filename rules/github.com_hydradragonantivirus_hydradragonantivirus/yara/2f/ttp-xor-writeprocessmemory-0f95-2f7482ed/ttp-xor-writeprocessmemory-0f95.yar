rule TTP_XOR_WriteProcessMemory_0f95 {
  strings:
    $key_0f95 = { 58 e7 [2] 6a c5 [2] 6c f0 [2] 42 f0 [2] 7d ec }

  condition:
    any of them
}