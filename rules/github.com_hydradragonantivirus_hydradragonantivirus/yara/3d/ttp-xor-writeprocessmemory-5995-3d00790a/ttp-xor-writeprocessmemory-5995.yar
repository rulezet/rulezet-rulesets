rule TTP_XOR_WriteProcessMemory_5995 {
  strings:
    $key_5995 = { 0e e7 [2] 3c c5 [2] 3a f0 [2] 14 f0 [2] 2b ec }

  condition:
    any of them
}