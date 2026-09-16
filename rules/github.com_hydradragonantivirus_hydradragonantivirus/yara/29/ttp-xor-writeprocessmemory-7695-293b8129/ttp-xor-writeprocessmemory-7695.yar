rule TTP_XOR_WriteProcessMemory_7695 {
  strings:
    $key_7695 = { 21 e7 [2] 13 c5 [2] 15 f0 [2] 3b f0 [2] 04 ec }

  condition:
    any of them
}