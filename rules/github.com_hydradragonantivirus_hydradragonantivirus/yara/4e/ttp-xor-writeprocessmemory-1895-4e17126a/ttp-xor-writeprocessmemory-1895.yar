rule TTP_XOR_WriteProcessMemory_1895 {
  strings:
    $key_1895 = { 4f e7 [2] 7d c5 [2] 7b f0 [2] 55 f0 [2] 6a ec }

  condition:
    any of them
}