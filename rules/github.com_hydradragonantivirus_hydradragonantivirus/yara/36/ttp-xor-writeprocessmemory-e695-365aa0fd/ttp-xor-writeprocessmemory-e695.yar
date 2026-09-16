rule TTP_XOR_WriteProcessMemory_e695 {
  strings:
    $key_e695 = { b1 e7 [2] 83 c5 [2] 85 f0 [2] ab f0 [2] 94 ec }

  condition:
    any of them
}