rule TTP_XOR_WriteProcessMemory_2895 {
  strings:
    $key_2895 = { 7f e7 [2] 4d c5 [2] 4b f0 [2] 65 f0 [2] 5a ec }

  condition:
    any of them
}