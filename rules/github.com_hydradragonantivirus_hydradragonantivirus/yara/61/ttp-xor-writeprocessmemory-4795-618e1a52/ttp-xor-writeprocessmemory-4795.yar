rule TTP_XOR_WriteProcessMemory_4795 {
  strings:
    $key_4795 = { 10 e7 [2] 22 c5 [2] 24 f0 [2] 0a f0 [2] 35 ec }

  condition:
    any of them
}