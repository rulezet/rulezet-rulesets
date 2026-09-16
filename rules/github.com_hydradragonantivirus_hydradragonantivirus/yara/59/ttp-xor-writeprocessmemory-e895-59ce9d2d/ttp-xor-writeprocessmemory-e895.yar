rule TTP_XOR_WriteProcessMemory_e895 {
  strings:
    $key_e895 = { bf e7 [2] 8d c5 [2] 8b f0 [2] a5 f0 [2] 9a ec }

  condition:
    any of them
}