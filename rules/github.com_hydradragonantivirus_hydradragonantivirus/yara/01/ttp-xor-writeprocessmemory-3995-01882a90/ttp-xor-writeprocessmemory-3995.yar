rule TTP_XOR_WriteProcessMemory_3995 {
  strings:
    $key_3995 = { 6e e7 [2] 5c c5 [2] 5a f0 [2] 74 f0 [2] 4b ec }

  condition:
    any of them
}