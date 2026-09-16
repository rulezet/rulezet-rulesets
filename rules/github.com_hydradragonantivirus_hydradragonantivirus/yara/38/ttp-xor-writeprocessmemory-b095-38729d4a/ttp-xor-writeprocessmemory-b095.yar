rule TTP_XOR_WriteProcessMemory_b095 {
  strings:
    $key_b095 = { e7 e7 [2] d5 c5 [2] d3 f0 [2] fd f0 [2] c2 ec }

  condition:
    any of them
}