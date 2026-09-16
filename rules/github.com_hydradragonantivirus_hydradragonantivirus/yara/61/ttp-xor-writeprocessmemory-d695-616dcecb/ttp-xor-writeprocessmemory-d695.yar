rule TTP_XOR_WriteProcessMemory_d695 {
  strings:
    $key_d695 = { 81 e7 [2] b3 c5 [2] b5 f0 [2] 9b f0 [2] a4 ec }

  condition:
    any of them
}