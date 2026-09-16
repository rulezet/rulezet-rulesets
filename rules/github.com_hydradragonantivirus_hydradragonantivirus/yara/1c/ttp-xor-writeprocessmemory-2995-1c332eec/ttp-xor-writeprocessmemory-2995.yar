rule TTP_XOR_WriteProcessMemory_2995 {
  strings:
    $key_2995 = { 7e e7 [2] 4c c5 [2] 4a f0 [2] 64 f0 [2] 5b ec }

  condition:
    any of them
}