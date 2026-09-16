rule TTP_XOR_WriteProcessMemory_6995 {
  strings:
    $key_6995 = { 3e e7 [2] 0c c5 [2] 0a f0 [2] 24 f0 [2] 1b ec }

  condition:
    any of them
}