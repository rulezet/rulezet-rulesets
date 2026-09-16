rule TTP_XOR_WriteProcessMemory_c595 {
  strings:
    $key_c595 = { 92 e7 [2] a0 c5 [2] a6 f0 [2] 88 f0 [2] b7 ec }

  condition:
    any of them
}