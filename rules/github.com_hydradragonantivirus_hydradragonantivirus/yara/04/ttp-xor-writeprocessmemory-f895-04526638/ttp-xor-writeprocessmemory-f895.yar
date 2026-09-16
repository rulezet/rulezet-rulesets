rule TTP_XOR_WriteProcessMemory_f895 {
  strings:
    $key_f895 = { af e7 [2] 9d c5 [2] 9b f0 [2] b5 f0 [2] 8a ec }

  condition:
    any of them
}