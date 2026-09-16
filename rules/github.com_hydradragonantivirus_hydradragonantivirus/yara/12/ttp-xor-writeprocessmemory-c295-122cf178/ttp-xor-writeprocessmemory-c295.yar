rule TTP_XOR_WriteProcessMemory_c295 {
  strings:
    $key_c295 = { 95 e7 [2] a7 c5 [2] a1 f0 [2] 8f f0 [2] b0 ec }

  condition:
    any of them
}