rule TTP_XOR_WriteProcessMemory_c095 {
  strings:
    $key_c095 = { 97 e7 [2] a5 c5 [2] a3 f0 [2] 8d f0 [2] b2 ec }

  condition:
    any of them
}