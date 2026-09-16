rule TTP_XOR_WriteProcessMemory_5595 {
  strings:
    $key_5595 = { 02 e7 [2] 30 c5 [2] 36 f0 [2] 18 f0 [2] 27 ec }

  condition:
    any of them
}