rule TTP_XOR_WriteProcessMemory_d295 {
  strings:
    $key_d295 = { 85 e7 [2] b7 c5 [2] b1 f0 [2] 9f f0 [2] a0 ec }

  condition:
    any of them
}