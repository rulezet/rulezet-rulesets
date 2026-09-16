rule TTP_XOR_WriteProcessMemory_4395 {
  strings:
    $key_4395 = { 14 e7 [2] 26 c5 [2] 20 f0 [2] 0e f0 [2] 31 ec }

  condition:
    any of them
}