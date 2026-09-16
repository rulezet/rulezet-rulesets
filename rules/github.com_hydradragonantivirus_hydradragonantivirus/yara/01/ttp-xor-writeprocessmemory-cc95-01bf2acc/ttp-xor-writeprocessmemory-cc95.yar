rule TTP_XOR_WriteProcessMemory_cc95 {
  strings:
    $key_cc95 = { 9b e7 [2] a9 c5 [2] af f0 [2] 81 f0 [2] be ec }

  condition:
    any of them
}