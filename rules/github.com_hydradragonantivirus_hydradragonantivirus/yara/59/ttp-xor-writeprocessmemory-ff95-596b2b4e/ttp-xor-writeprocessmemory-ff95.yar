rule TTP_XOR_WriteProcessMemory_ff95 {
  strings:
    $key_ff95 = { a8 e7 [2] 9a c5 [2] 9c f0 [2] b2 f0 [2] 8d ec }

  condition:
    any of them
}