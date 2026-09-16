rule TTP_XOR_WriteProcessMemory_7895 {
  strings:
    $key_7895 = { 2f e7 [2] 1d c5 [2] 1b f0 [2] 35 f0 [2] 0a ec }

  condition:
    any of them
}