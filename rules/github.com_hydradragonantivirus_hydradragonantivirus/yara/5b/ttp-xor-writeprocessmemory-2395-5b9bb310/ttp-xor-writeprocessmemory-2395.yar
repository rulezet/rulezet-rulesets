rule TTP_XOR_WriteProcessMemory_2395 {
  strings:
    $key_2395 = { 74 e7 [2] 46 c5 [2] 40 f0 [2] 6e f0 [2] 51 ec }

  condition:
    any of them
}