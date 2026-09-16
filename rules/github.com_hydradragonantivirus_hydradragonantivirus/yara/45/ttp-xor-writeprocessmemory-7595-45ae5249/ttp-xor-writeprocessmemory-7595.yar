rule TTP_XOR_WriteProcessMemory_7595 {
  strings:
    $key_7595 = { 22 e7 [2] 10 c5 [2] 16 f0 [2] 38 f0 [2] 07 ec }

  condition:
    any of them
}