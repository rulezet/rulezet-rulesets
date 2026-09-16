rule TTP_XOR_WriteProcessMemory_c195 {
  strings:
    $key_c195 = { 96 e7 [2] a4 c5 [2] a2 f0 [2] 8c f0 [2] b3 ec }

  condition:
    any of them
}