rule TTP_XOR_WriteProcessMemory_5695 {
  strings:
    $key_5695 = { 01 e7 [2] 33 c5 [2] 35 f0 [2] 1b f0 [2] 24 ec }

  condition:
    any of them
}