rule TTP_XOR_WriteProcessMemory_3395 {
  strings:
    $key_3395 = { 64 e7 [2] 56 c5 [2] 50 f0 [2] 7e f0 [2] 41 ec }

  condition:
    any of them
}