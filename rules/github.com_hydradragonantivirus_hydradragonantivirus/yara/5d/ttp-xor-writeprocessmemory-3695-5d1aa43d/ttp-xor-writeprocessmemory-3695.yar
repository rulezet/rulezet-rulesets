rule TTP_XOR_WriteProcessMemory_3695 {
  strings:
    $key_3695 = { 61 e7 [2] 53 c5 [2] 55 f0 [2] 7b f0 [2] 44 ec }

  condition:
    any of them
}