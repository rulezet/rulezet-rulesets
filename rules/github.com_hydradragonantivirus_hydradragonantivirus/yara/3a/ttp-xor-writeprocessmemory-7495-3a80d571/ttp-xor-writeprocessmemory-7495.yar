rule TTP_XOR_WriteProcessMemory_7495 {
  strings:
    $key_7495 = { 23 e7 [2] 11 c5 [2] 17 f0 [2] 39 f0 [2] 06 ec }

  condition:
    any of them
}